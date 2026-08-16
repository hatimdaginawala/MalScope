const { Analysis, ANALYSIS_STATUS } = require('../models/Analysis');
const MalwareSample = require('../models/MalwareSample');
const StaticAnalysis = require('../models/StaticAnalysis');
const DynamicAnalysis = require('../models/DynamicAnalysis');
const ThreatAssessment = require('../models/ThreatAssessment');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class AnalysisService {
  /**
   * Get analysis by ID
   */
  static async getAnalysisById(analysisId) {
    try {
      const analysis = await Analysis.findById(analysisId)
        .populate('sample')
        .populate('staticAnalysis')
        // .populate('dynamicAnalysis') // REMOVED - no longer in scope
        .populate('virusTotalReport')
        .populate('threatAssessment')
        .populate('configurationIndicators')
        .populate('similarityResults')
        .populate('malwareFamily')
        .populate('iocs')
        .populate('behaviors')
        .lean();
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      return analysis;
    } catch (error) {
      logger.error(`Failed to get analysis: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get analyses for a sample
   */
  static async getAnalysesForSample(sampleId, page = 1, limit = 10) {
    try {
      const skip = (page - 1) * limit;

      const [analyses, total] = await Promise.all([
        Analysis.find({ sample: sampleId })
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .populate('staticAnalysis')
          // .populate('dynamicAnalysis')
          .populate('virusTotalReport')
          .populate('threatAssessment')
          .lean(),
        Analysis.countDocuments({ sample: sampleId }),
      ]);

      return {
        analyses,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      logger.error(`Failed to get analyses: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Update analysis status
   */
// In analysisService.js, ensure the updateStatus method is working

static async updateStatus(analysisId, newStatus, logMessage = null) {
  try {
    const analysis = await Analysis.findById(analysisId);
    if (!analysis) {
      throw new ApiError(404, 'Analysis not found');
    }

    await analysis.updateStatus(newStatus, logMessage);
    await analysis.save();

    // If analysis is completed, update sample status
    if (newStatus === 'completed') {
      await MalwareSample.findByIdAndUpdate(analysis.sample, {
        status: 'completed',
      });
    }

    // If analysis failed, update sample status
    if (newStatus === 'failed') {
      await MalwareSample.findByIdAndUpdate(analysis.sample, {
        status: 'failed',
      });
    }

    logger.info(`Analysis ${analysisId} status updated to: ${newStatus}`);
    return analysis;
  } catch (error) {
    logger.error(`Failed to update analysis status: ${error.message}`, { error });
    throw error;
  }
}

  /**
   * Set analysis error
   */

static async setError(analysisId, errorMessage, errorStage, errorStack = null) {
  try {
    const analysis = await Analysis.findById(analysisId);
    if (!analysis) {
      throw new ApiError(404, 'Analysis not found');
    }

    // Use a valid stage value from ANALYSIS_STATUS
    const validStages = ['queued', 'preparing', 'static_analysis', 'vt_enrichment', 
                         'dynamic_analysis', 'collecting', 'correlating', 'completed', 
                         'failed', 'cleanup'];
    
    const stage = validStages.includes(errorStage) ? errorStage : 'failed';

    await analysis.setError(errorMessage, stage, errorStack);
    await analysis.save();

    // Update sample status
    await MalwareSample.findByIdAndUpdate(analysis.sample, {
      status: 'failed',
    });

    return analysis;
  } catch (error) {
    logger.error(`Failed to set analysis error: ${error.message}`, { error });
    throw error;
  }
}
  /**
   * Add log entry to analysis
   */
  static async addLog(analysisId, message, level = 'info') {
    try {
      const analysis = await Analysis.findById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      await analysis.addLog(message, level);
      await analysis.save();

      return analysis;
    } catch (error) {
      logger.error(`Failed to add log: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Create a new analysis for a sample
   */
  static async createAnalysis(sampleId) {
    try {
      const sample = await MalwareSample.findById(sampleId);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      // Check if there's already a pending analysis
      const existing = await Analysis.findOne({
        sample: sampleId,
        status: { $nin: ['completed', 'failed', 'cleanup'] },
      });

      if (existing) {
        return existing;
      }

      const analysis = new Analysis({
        sample: sampleId,
        status: ANALYSIS_STATUS.QUEUED,
        stage: ANALYSIS_STATUS.QUEUED,
        environment: {
          nodeVersion: process.version,
        },
      });

      await analysis.save();

      // Update sample status
      await MalwareSample.findByIdAndUpdate(sampleId, {
        status: 'processing',
      });

      await sample.incrementAnalysisCount();

      logger.info(`Analysis created for sample: ${sample.sha256} (${analysis._id})`);
      return analysis;
    } catch (error) {
      logger.error(`Failed to create analysis: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Check if analysis can proceed
   */
  static async canProceed(analysisId) {
    try {
      const analysis = await Analysis.findById(analysisId);
      if (!analysis) {
        return false;
      }

      // Can't proceed if completed, failed, or in cleanup
      const blocked = ['completed', 'failed', 'cleanup'];
      return !blocked.includes(analysis.status);
    } catch (error) {
      logger.error(`Failed to check analysis status: ${error.message}`, { error });
      return false;
    }
  }

  /**
   * Get analysis statistics
   */
  static async getStats() {
    try {
      const [total, queued, running, completed, failed] = await Promise.all([
        Analysis.countDocuments(),
        Analysis.countDocuments({ status: 'queued' }),
        Analysis.countDocuments({
          status: { $in: ['preparing', 'static_analysis', 'vt_enrichment', 'dynamic_analysis', 'collecting', 'correlating'] },
        }),
        Analysis.countDocuments({ status: 'completed' }),
        Analysis.countDocuments({ status: 'failed' }),
      ]);

      return {
        total,
        queued,
        running,
        completed,
        failed,
      };
    } catch (error) {
      logger.error(`Failed to get analysis stats: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Cleanup an analysis (failed or completed)
   */
  static async cleanupAnalysis(analysisId) {
    try {
      const analysis = await Analysis.findById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      await analysis.updateStatus('cleanup', 'Cleaning up analysis resources');
      await analysis.save();

      // Additional cleanup logic can be added here
      // (e.g., VM cleanup, temporary file removal)

      return analysis;
    } catch (error) {
      logger.error(`Failed to cleanup analysis: ${error.message}`, { error });
      throw error;
    }
  }
}

module.exports = AnalysisService;