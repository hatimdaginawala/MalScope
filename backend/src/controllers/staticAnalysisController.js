const StaticAnalysisService = require('../services/staticAnalysisService');
const AnalysisService = require('../services/analysisService');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class StaticAnalysisController {
  /**
   * Get static analysis results
   * GET /api/v1/analyses/:analysisId/static
   */
  static async getResults(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await StaticAnalysisService.getResults(analysisId);

      res.status(200).json({
        success: true,
        data: results,
      });
    } catch (error) {
      logger.error(`Failed to get static analysis results: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get static analysis summary
   * GET /api/v1/analyses/:analysisId/static/summary
   */
  static async getSummary(req, res, next) {
    try {
      const { analysisId } = req.params;

      const summary = await StaticAnalysisService.getSummary(analysisId);

      res.status(200).json({
        success: true,
        data: summary,
      });
    } catch (error) {
      logger.error(`Failed to get static analysis summary: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get static analysis YARA matches
   * GET /api/v1/analyses/:analysisId/static/yara
   */
  static async getYaraMatches(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await StaticAnalysisService.getResults(analysisId);
      const yaraMatches = results.yaraMatches || [];

      res.status(200).json({
        success: true,
        data: {
          total: yaraMatches.length,
          matches: yaraMatches,
        },
      });
    } catch (error) {
      logger.error(`Failed to get YARA matches: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get static analysis findings
   * GET /api/v1/analyses/:analysisId/static/findings
   */
  static async getFindings(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await StaticAnalysisService.getResults(analysisId);
      const findings = results.findings || [];

      // Filter by severity if requested
      const severity = req.query.severity;
      const filteredFindings = severity
        ? findings.filter(f => f.severity === severity)
        : findings;

      res.status(200).json({
        success: true,
        data: {
          total: filteredFindings.length,
          findings: filteredFindings,
          bySeverity: this._groupBySeverity(findings),
        },
      });
    } catch (error) {
      logger.error(`Failed to get static analysis findings: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get static analysis PE info
   * GET /api/v1/analyses/:analysisId/static/pe-info
   */
  static async getPEInfo(req, res, next) {
    try {
      const { analysisId } = req.params;

      const results = await StaticAnalysisService.getResults(analysisId);
      const peInfo = {
        fileInfo: results.fileInfo || {},
        sections: results.sections || [],
        imports: results.imports || [],
        exports: results.exports || [],
        resources: results.resources || [],
        entropy: results.entropy || {},
        strings: results.strings || {},
      };

      res.status(200).json({
        success: true,
        data: peInfo,
      });
    } catch (error) {
      logger.error(`Failed to get PE info: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Group findings by severity
   */
  static _groupBySeverity(findings) {
    const groups = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    for (const finding of findings) {
      const severity = finding.severity || 'low';
      if (groups[severity] !== undefined) {
        groups[severity]++;
      }
    }

    return groups;
  }

  /**
   * Check if static analysis exists
   * GET /api/v1/analyses/:analysisId/static/exists
   */
  static async exists(req, res, next) {
    try {
      const { analysisId } = req.params;

      const analysis = await AnalysisService.getAnalysisById(analysisId);
      const exists = analysis && analysis.staticAnalysis;

      res.status(200).json({
        success: true,
        data: { exists },
      });
    } catch (error) {
      logger.error(`Failed to check static analysis existence: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Rerun static analysis
   * POST /api/v1/analyses/:analysisId/static/rerun
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
      await AnalysisService.updateStatus(analysisId, 'static_analysis', 'Rerunning static analysis');

      // Run static analysis
      const result = await StaticAnalysisService.analyze(analysisId);

      res.status(200).json({
        success: true,
        message: 'Static analysis rerun completed',
        data: result,
      });
    } catch (error) {
      logger.error(`Failed to rerun static analysis: ${error.message}`, { error });
      next(error);
    }
  }
}

module.exports = StaticAnalysisController;