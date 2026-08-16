const DynamicAnalysisService = require('../services/dynamicAnalysisService');
const AnalysisService = require('../services/analysisService');
const VirtualBoxService = require('../services/virtualBoxService');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class DynamicAnalysisController {
  /**
   * Get dynamic analysis results
   * GET /api/v1/analyses/:analysisId/dynamic
   */
  static async getResults(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await DynamicAnalysisService.getResults(analysisId);

      res.status(200).json({
        success: true,
        data: results,
      });
    } catch (error) {
      logger.error(`Failed to get dynamic analysis results: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get dynamic analysis summary
   * GET /api/v1/analyses/:analysisId/dynamic/summary
   */
  static async getSummary(req, res, next) {
    try {
      const { analysisId } = req.params;

      const summary = await DynamicAnalysisService.getSummary(analysisId);

      res.status(200).json({
        success: true,
        data: summary,
      });
    } catch (error) {
      logger.error(`Failed to get dynamic analysis summary: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get dynamic analysis process activity
   * GET /api/v1/analyses/:analysisId/dynamic/processes
   */
  static async getProcesses(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await DynamicAnalysisService.getResults(analysisId);
      const processes = results.processes || [];

      // Filter by PID if provided
      const pid = req.query.pid ? parseInt(req.query.pid) : null;
      const filteredProcesses = pid
        ? processes.filter(p => p.pid === pid)
        : processes;

      res.status(200).json({
        success: true,
        data: {
          total: filteredProcesses.length,
          processes: filteredProcesses,
        },
      });
    } catch (error) {
      logger.error(`Failed to get processes: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get dynamic analysis network activity
   * GET /api/v1/analyses/:analysisId/dynamic/network
   */
  static async getNetworkEvents(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await DynamicAnalysisService.getResults(analysisId);
      const networkEvents = results.networkEvents || [];

      // Filter by protocol if provided
      const protocol = req.query.protocol;
      const filteredEvents = protocol
        ? networkEvents.filter(e => e.protocol === protocol)
        : networkEvents;

      res.status(200).json({
        success: true,
        data: {
          total: filteredEvents.length,
          events: filteredEvents,
        },
      });
    } catch (error) {
      logger.error(`Failed to get network events: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get dynamic analysis file activity
   * GET /api/v1/analyses/:analysisId/dynamic/files
   */
  static async getFileEvents(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await DynamicAnalysisService.getResults(analysisId);
      const fileEvents = results.fileEvents || [];

      // Filter by operation if provided
      const operation = req.query.operation;
      const filteredEvents = operation
        ? fileEvents.filter(e => e.operation === operation)
        : fileEvents;

      res.status(200).json({
        success: true,
        data: {
          total: filteredEvents.length,
          events: filteredEvents,
        },
      });
    } catch (error) {
      logger.error(`Failed to get file events: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get dynamic analysis registry activity
   * GET /api/v1/analyses/:analysisId/dynamic/registry
   */
  static async getRegistryEvents(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await DynamicAnalysisService.getResults(analysisId);
      const registryEvents = results.registryEvents || [];

      res.status(200).json({
        success: true,
        data: {
          total: registryEvents.length,
          events: registryEvents,
        },
      });
    } catch (error) {
      logger.error(`Failed to get registry events: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get persistence mechanisms
   * GET /api/v1/analyses/:analysisId/dynamic/persistence
   */
  static async getPersistence(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await DynamicAnalysisService.getResults(analysisId);
      const persistence = results.persistence || [];

      res.status(200).json({
        success: true,
        data: {
          total: persistence.length,
          mechanisms: persistence,
        },
      });
    } catch (error) {
      logger.error(`Failed to get persistence mechanisms: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get behaviors from dynamic analysis
   * GET /api/v1/analyses/:analysisId/dynamic/behaviors
   */
  static async getBehaviors(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await DynamicAnalysisService.getResults(analysisId);
      const behaviors = results.behaviors || [];

      // Filter by severity if requested
      const severity = req.query.severity;
      const filteredBehaviors = severity
        ? behaviors.filter(b => b.severity === severity)
        : behaviors;

      res.status(200).json({
        success: true,
        data: {
          total: filteredBehaviors.length,
          behaviors: filteredBehaviors,
          bySeverity: this._groupBySeverity(behaviors),
        },
      });
    } catch (error) {
      logger.error(`Failed to get behaviors: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Check VM status
   * GET /api/v1/dynamic/vm-status
   */
  static async getVMStatus(req, res, next) {
    try {
      const vboxAvailable = await VirtualBoxService.isVirtualBoxAvailable();
      const vmExists = vboxAvailable ? await VirtualBoxService.vmExists() : false;
      const vmState = vboxAvailable && vmExists ? await VirtualBoxService.getVMState() : 'unknown';
      const snapshotExists = vboxAvailable && vmExists ? await VirtualBoxService.snapshotExists() : false;

      res.status(200).json({
        success: true,
        data: {
          virtualBoxAvailable: vboxAvailable,
          vmExists,
          vmState,
          vmName: VirtualBoxService.vmName,
          snapshotExists,
          snapshotName: VirtualBoxService.snapshotName,
          isReady: vmState === 'running',
        },
      });
    } catch (error) {
      logger.error(`Failed to get VM status: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Group behaviors by severity
   */
  static _groupBySeverity(behaviors) {
    const groups = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    for (const behavior of behaviors) {
      const severity = behavior.severity || 'low';
      if (groups[severity] !== undefined) {
        groups[severity]++;
      }
    }

    return groups;
  }

  /**
   * Check if dynamic analysis exists
   * GET /api/v1/analyses/:analysisId/dynamic/exists
   */
  static async exists(req, res, next) {
    try {
      const { analysisId } = req.params;

      const analysis = await AnalysisService.getAnalysisById(analysisId);
      const exists = analysis && analysis.dynamicAnalysis;

      res.status(200).json({
        success: true,
        data: { exists },
      });
    } catch (error) {
      logger.error(`Failed to check dynamic analysis existence: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Rerun dynamic analysis
   * POST /api/v1/analyses/:analysisId/dynamic/rerun
   */
  static async rerun(req, res, next) {
    try {
      const { analysisId } = req.params;

      // Check if analysis exists and can be rerun
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      // Update status
      await AnalysisService.updateStatus(analysisId, 'dynamic_analysis', 'Rerunning dynamic analysis');

      // Run dynamic analysis with options
      const options = {
        executionTimeout: req.body.timeout || 60000,
      };

      const result = await DynamicAnalysisService.analyze(analysisId, options);

      res.status(200).json({
        success: true,
        message: 'Dynamic analysis rerun completed',
        data: result,
      });
    } catch (error) {
      logger.error(`Failed to rerun dynamic analysis: ${error.message}`, { error });
      next(error);
    }
  }
}

module.exports = DynamicAnalysisController;