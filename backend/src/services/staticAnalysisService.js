const StaticAnalysis = require('../models/StaticAnalysis');
const MalwareSample = require('../models/MalwareSample');
const AnalysisService = require('./analysisService');
const PythonAnalysisService = require('./pythonAnalysisService');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class StaticAnalysisService {
  /**
   * Perform static analysis on a sample
   */
  static async analyze(analysisId) {
    try {
      // Get analysis
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      // Check if we can proceed
      const canProceed = await AnalysisService.canProceed(analysisId);
      if (!canProceed) {
        throw new ApiError(400, `Analysis cannot proceed in current state: ${analysis.status}`);
      }

      // Update status
      await AnalysisService.updateStatus(analysisId, 'static_analysis', 'Starting static analysis');

      // Get sample
      const sample = await MalwareSample.findById(analysis.sample);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      // Run Python static analysis
      let pythonResult;
      try {
        pythonResult = await PythonAnalysisService.runStaticAnalysis(sample.storagePath);
      } catch (error) {
        await AnalysisService.setError(analysisId, `Python analysis failed: ${error.message}`, 'static_analysis');
        throw error;
      }

      // Check if Python analysis succeeded
      if (!pythonResult.success) {
        const errorMsg = pythonResult.errors ? pythonResult.errors.join(', ') : 'Unknown Python error';
        await AnalysisService.setError(analysisId, errorMsg, 'static_analysis');
        throw new ApiError(500, `Static analysis failed: ${errorMsg}`);
      }

      // Create StaticAnalysis record
      const staticAnalysis = new StaticAnalysis({
        sample: sample._id,
        analysis: analysisId,
        fileInfo: pythonResult.result.file || {},
        sections: pythonResult.result.sections || [],
        imports: pythonResult.result.imports || [],
        exports: pythonResult.result.exports || [],
        strings: pythonResult.result.strings || {},
        entropy: pythonResult.result.entropy || {},
        resources: pythonResult.result.resources || [],
        yaraMatches: pythonResult.result.yaraMatches || [],
        findings: pythonResult.result.findings || [],
        processedAt: new Date(),
        processingDuration: pythonResult.duration || 0,
        warnings: pythonResult.warnings || [],
        errors: pythonResult.errors || [],
        version: '1.0.0',
        rawResult: pythonResult.result,
      });

      await staticAnalysis.save();

      // Update analysis with staticAnalysis reference
      analysis.staticAnalysis = staticAnalysis._id;
      await analysis.save();

      await AnalysisService.addLog(analysisId, 'Static analysis completed successfully', 'info');

      return {
        staticAnalysis,
        pythonResult,
        warnings: pythonResult.warnings || [],
        errors: pythonResult.errors || [],
      };
    } catch (error) {
      logger.error(`Static analysis failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get static analysis results
   */
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

  /**
   * Get static analysis summary
   */
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

  /**
   * Check if sample has been statically analyzed
   */
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