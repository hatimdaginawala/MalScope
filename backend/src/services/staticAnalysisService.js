const StaticAnalysis = require('../models/StaticAnalysis');
const MalwareSample = require('../models/MalwareSample');
const { Analysis } = require('../models/Analysis');
const AnalysisService = require('./analysisService');
const PythonAnalysisService = require('./pythonAnalysisService');
const IOC = require('../models/IOC');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class StaticAnalysisService {
  static async analyze(analysisId) {
    try {
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      const canProceed = await AnalysisService.canProceed(analysisId);
      if (!canProceed) {
        throw new ApiError(400, `Analysis cannot proceed in current state: ${analysis.status}`);
      }

      await AnalysisService.updateStatus(analysisId, 'static_analysis', 'Starting static analysis');

      const sample = await MalwareSample.findById(analysis.sample);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      let pythonResult;
      try {
        pythonResult = await PythonAnalysisService.runStaticAnalysis(sample.storagePath);
      } catch (error) {
        await AnalysisService.setError(analysisId, `Python analysis failed: ${error.message}`, 'static_analysis');
        throw error;
      }

      if (!pythonResult.success) {
        const errorMsg = pythonResult.errors ? pythonResult.errors.join(', ') : 'Unknown Python error';
        await AnalysisService.setError(analysisId, errorMsg, 'static_analysis');
        throw new ApiError(500, `Static analysis failed: ${errorMsg}`);
      }

      const result = pythonResult.result || {};

      // Create StaticAnalysis record
      const staticAnalysis = new StaticAnalysis({
        sample: sample._id,
        analysis: analysisId,
        fileInfo: result.file || {},
        sections: result.sections || [],
        imports: result.imports || [],
        exports: result.exports || [],
        strings: result.strings || { ascii: [], unicode: [], suspicious: [] },
        entropy: result.entropy || { overall: 0, sections: [], highEntropySections: [] },
        resources: result.resources || [],
        yaraMatches: result.yaraMatches || [],
        findings: result.findings || [],
        processedAt: new Date(),
        processingDuration: pythonResult.duration || 0,
        warnings: pythonResult.warnings || [],
        errors: pythonResult.errors || [],
        version: '1.0.0',
        rawResult: result,
      });

      await staticAnalysis.save();

      // ===== Extract IOCs from Python result =====
      const pythonIOCs = result.iocs || [];
      logger.info(`Found ${pythonIOCs.length} IOCs from Python analysis`);
      
      let savedCount = 0;
      for (const iocData of pythonIOCs) {
        try {
          const type = iocData.type || 'other';
          const value = iocData.value || '';
          
          if (!value) {
            logger.warn(`Skipping IOC with empty value`);
            continue;
          }
          
          const normalizedValue = value.toLowerCase().trim();
          
          // Check if IOC already exists for this sample
          const existing = await IOC.findOne({
            sample: sample._id,
            type: type,
            normalizedValue: normalizedValue,
          });
          
          if (!existing) {
            const newIOC = new IOC({
              type: type,
              value: value,
              normalizedValue: normalizedValue,
              source: 'static_analysis',
              sample: sample._id,
              analysis: analysisId,  // <-- IMPORTANT: Set analysis ID
              confidence: iocData.confidence || 0.5,
              severity: 'medium',
              context: iocData.context || {},
              tags: [],
              firstSeen: new Date(),
              lastSeen: new Date(),
            });
            await newIOC.save();
            savedCount++;
            logger.debug(`Saved IOC: ${type}:${value}`);
          } else {
            existing.lastSeen = new Date();
            existing.confidence = Math.max(existing.confidence, iocData.confidence || 0.5);
            await existing.save();
            savedCount++;
          }
        } catch (iocError) {
          logger.warn(`Failed to save IOC: ${iocError.message}`);
        }
      }
      
      logger.info(`Saved ${savedCount} IOCs for sample ${sample._id}`);

      // Update analysis with staticAnalysis reference
      await Analysis.updateOne(
        { _id: analysisId },
        { staticAnalysis: staticAnalysis._id }
      );

      await AnalysisService.addLog(analysisId, 'Static analysis completed successfully', 'info');

      return {
        staticAnalysis,
        pythonResult,
        iocs: pythonIOCs,
        warnings: pythonResult.warnings || [],
        errors: pythonResult.errors || [],
      };
    } catch (error) {
      logger.error(`Static analysis failed: ${error.message}`, { error });
      throw error;
    }
  }

  static async getResults(analysisId) {
    try {
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      if (!analysis.staticAnalysis) {
        throw new ApiError(404, 'Static analysis not found for this analysis');
      }

      const staticAnalysis = await StaticAnalysis.findById(analysis.staticAnalysis)
        .populate('sample', 'filename sha256 md5 fileSize')
        .lean();

      if (!staticAnalysis) {
        throw new ApiError(404, 'Static analysis results not found');
      }

      return staticAnalysis;
    } catch (error) {
      logger.error(`Failed to get static analysis results: ${error.message}`, { error });
      throw error;
    }
  }

  static async getSummary(analysisId) {
    try {
      const results = await this.getResults(analysisId);
      
      return {
        fileInfo: results.fileInfo,
        summary: {
          totalSections: results.sections ? results.sections.length : 0,
          totalImports: results.imports ? results.imports.reduce((acc, imp) => acc + imp.functions.length, 0) : 0,
          totalExports: results.exports ? results.exports.length : 0,
          yaraMatches: results.yaraMatches ? results.yaraMatches.length : 0,
          findings: results.findings ? results.findings.length : 0,
          suspiciousStrings: results.strings && results.strings.suspicious ? results.strings.suspicious.length : 0,
        },
        findings: results.findings || [],
        yaraMatches: results.yaraMatches || [],
        processedAt: results.processedAt,
      };
    } catch (error) {
      logger.error(`Failed to get static analysis summary: ${error.message}`, { error });
      throw error;
    }
  }

  static async hasResults(sampleId) {
    try {
      const count = await StaticAnalysis.countDocuments({ sample: sampleId });
      return count > 0;
    } catch (error) {
      logger.error(`Failed to check static analysis results: ${error.message}`, { error });
      return false;
    }
  }
}

module.exports = StaticAnalysisService;