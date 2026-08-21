const AnalysisService = require('../services/analysisService');
const StaticAnalysisService = require('../services/staticAnalysisService');
// const DynamicAnalysisService = require('../services/dynamicAnalysisService');
const VirusTotalService = require('../services/virusTotalService');
const CorrelationService = require('../services/correlationService');
const RiskService = require('../services/riskService');
const SampleService = require('../services/sampleService');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');
const { ANALYSIS_STATUS } = require('../models/Analysis');

class AnalysisController {
  /**
   * Start a new analysis
   * POST /api/v1/analyses
   */
  static async startAnalysis(req, res, next) {
    try {
      const { sampleId, runDynamic = true, runVirusTotal = true } = req.body;

      if (!sampleId) {
        throw new ApiError(400, 'Sample ID is required');
      }

      // Check if sample exists
      const sample = await SampleService.getSampleById(sampleId);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      // Create analysis
      const analysis = await AnalysisService.createAnalysis(sampleId);

      // Start analysis asynchronously
      setImmediate(() => {
        AnalysisController._processAnalysis(analysis._id, { runDynamic, runVirusTotal })
          .catch(err => {
            logger.error(`Background analysis failed: ${err.message}`, { error: err });
          });
      });

      res.status(201).json({
        success: true,
        message: 'Analysis started successfully',
        data: {
          analysisId: analysis._id,
          status: analysis.status,
          sampleId: sample._id,
        },
      });
    } catch (error) {
      logger.error(`Failed to start analysis: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Process analysis (background task)
   */
/**
 * Process analysis (background task)
 */
/**
 * Process analysis (background task)
 */
static async _processAnalysis(analysisId, options) {
  try {
    const { runVirusTotal = true } = options;

    logger.info(`Starting background analysis: ${analysisId}`);

    // Step 1: Preparing
    await AnalysisService.updateStatus(analysisId, 'preparing', 'Preparing analysis');

    // Step 2: Static Analysis
    logger.info(`[${analysisId}] Running static analysis...`);
    await AnalysisService.updateStatus(analysisId, 'static_analysis', 'Starting static analysis');
    await StaticAnalysisService.analyze(analysisId);
    logger.info(`[${analysisId}] Static analysis completed`);

    // Step 3: VirusTotal Enrichment (only if not already completed)
    if (runVirusTotal && VirusTotalService.isEnabled()) {
      // Check if analysis is still in a state where we can do VT enrichment
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (analysis && analysis.status !== 'completed' && analysis.status !== 'failed') {
        logger.info(`[${analysisId}] Running VirusTotal enrichment...`);
        await AnalysisService.updateStatus(analysisId, 'vt_enrichment', 'Starting VirusTotal enrichment');
        if (analysis.sample) {
          const sample = await SampleService.getSampleById(analysis.sample);
          if (sample) {
            await VirusTotalService.enrichAnalysis(analysisId, sample._id, sample.sha256);
          }
        }
        logger.info(`[${analysisId}] VirusTotal enrichment completed`);
      } else {
        logger.info(`[${analysisId}] VirusTotal enrichment skipped - analysis already ${analysis?.status}`);
      }
    }

    // Step 4: Complete (only if not already completed)
    const finalAnalysis = await AnalysisService.getAnalysisById(analysisId);
    if (finalAnalysis && finalAnalysis.status !== 'completed' && finalAnalysis.status !== 'failed') {
      await AnalysisService.updateStatus(analysisId, 'completed', 'Analysis completed successfully');
      logger.info(`[${analysisId}] Analysis completed successfully!`);
    } else {
      logger.info(`[${analysisId}] Analysis already ${finalAnalysis?.status}`);
    }

  } catch (error) {
    logger.error(`[${analysisId}] Analysis processing failed: ${error.message}`, { error });
    try {
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (analysis && analysis.status !== 'failed') {
        await AnalysisService.setError(analysisId, error.message, 'analysis');
      }
    } catch (setError) {
      logger.error(`[${analysisId}] Failed to set error: ${setError.message}`);
    }
  }
}

  /**
   * Get analysis status
   * GET /api/v1/analyses/:id/status
   */
  static async getStatus(req, res, next) {
    try {
      const { id } = req.params;

      const analysis = await AnalysisService.getAnalysisById(id);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      const progress = AnalysisController._calculateProgress(analysis);

      res.status(200).json({
        success: true,
        data: {
          id: analysis._id,
          status: analysis.status,
          stage: analysis.stage,
          progress,
          startedAt: analysis.startedAt,
          completedAt: analysis.completedAt,
          duration: analysis.duration,
          error: analysis.errorInfo || analysis.error,
          logs: analysis.logs ? analysis.logs.slice(-10) : [],
          completed: analysis.completed,
        },
      });
    } catch (error) {
      logger.error(`Failed to get analysis status: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get analysis by ID
   * GET /api/v1/analyses/:id
   */
  static async getAnalysis(req, res, next) {
    try {
      const { id } = req.params;

      const analysis = await AnalysisService.getAnalysisById(id);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      res.status(200).json({
        success: true,
        data: analysis,
      });
    } catch (error) {
      logger.error(`Failed to get analysis: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get analyses for a sample
   * GET /api/v1/analyses/sample/:sampleId
   */
  static async getAnalysesForSample(req, res, next) {
    try {
      const { sampleId } = req.params;
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;

      const result = await AnalysisService.getAnalysesForSample(sampleId, page, limit);

      res.status(200).json({
        success: true,
        data: result.analyses,
        pagination: result.pagination,
      });
    } catch (error) {
      logger.error(`Failed to get analyses for sample: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Cancel analysis
   * POST /api/v1/analyses/:id/cancel
   */
  static async cancelAnalysis(req, res, next) {
    try {
      const { id } = req.params;

      const analysis = await AnalysisService.getAnalysisById(id);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      const cancellableStatuses = ['queued', 'preparing', 'static_analysis'];
      if (!cancellableStatuses.includes(analysis.status)) {
        throw new ApiError(400, `Analysis cannot be cancelled in current state: ${analysis.status}`);
      }

      await AnalysisService.setError(id, 'Analysis cancelled by user', analysis.status);

      res.status(200).json({
        success: true,
        message: 'Analysis cancelled successfully',
      });
    } catch (error) {
      logger.error(`Failed to cancel analysis: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Calculate analysis progress
   */
  static _calculateProgress(analysis) {
    const stages = {
      queued: 0,
      preparing: 5,
      static_analysis: 20,
      vt_enrichment: 40,
      dynamic_analysis: 55,
      collecting: 70,
      correlating: 85,
      completed: 100,
      failed: 0,
      cleanup: 95,
    };

    return stages[analysis.status] || 0;
  }

  /**
   * Get analysis statistics
   * GET /api/v1/analyses/stats
   */
  static async getStats(req, res, next) {
    try {
      const stats = await AnalysisService.getStats();

      res.status(200).json({
        success: true,
        data: stats,
      });
    } catch (error) {
      logger.error(`Failed to get analysis stats: ${error.message}`, { error });
      next(error);
    }
  }
}

module.exports = AnalysisController;