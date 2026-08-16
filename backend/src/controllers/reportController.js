const ReportService = require('../services/reportService');
const AnalysisService = require('../services/analysisService');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class ReportController {
  /**
   * Generate report for an analysis
   * POST /api/v1/reports/:analysisId
   */
  static async generateReport(req, res, next) {
    try {
      const { analysisId } = req.params;
      const { format = 'json' } = req.body;

      // Check if analysis exists and is completed
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      if (analysis.status !== 'completed' && analysis.status !== 'failed') {
        throw new ApiError(400, 'Analysis must be completed or failed to generate report');
      }

      const report = await ReportService.generateReport(analysisId);

      // Return in requested format
      if (format === 'json') {
        return res.status(200).json({
          success: true,
          data: report,
        });
      }

      // Other formats (PDF, HTML) would be implemented here
      // For now, return JSON with a note
      res.status(200).json({
        success: true,
        message: `Report generated in ${format} format`,
        data: report,
        note: `${format.toUpperCase()} export will be implemented in future versions`,
      });
    } catch (error) {
      logger.error(`Failed to generate report: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get report for an analysis
   * GET /api/v1/reports/:analysisId
   */
  static async getReport(req, res, next) {
    try {
      const { analysisId } = req.params;

      // Check if analysis exists
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      // Check if report exists
      const hasReport = await ReportService.hasReport(analysisId);
      if (!hasReport) {
        throw new ApiError(404, 'Report not found for this analysis');
      }

      const report = await ReportService.generateReport(analysisId);

      res.status(200).json({
        success: true,
        data: report,
      });
    } catch (error) {
      logger.error(`Failed to get report: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get report summary
   * GET /api/v1/reports/:analysisId/summary
   */
  static async getReportSummary(req, res, next) {
    try {
      const { analysisId } = req.params;

      const summary = await ReportService.generateSummary(analysisId);

      res.status(200).json({
        success: true,
        data: summary,
      });
    } catch (error) {
      logger.error(`Failed to get report summary: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Download report as JSON
   * GET /api/v1/reports/:analysisId/download/json
   */
  static async downloadJSON(req, res, next) {
    try {
      const { analysisId } = req.params;

      const report = await ReportService.exportJSON(analysisId);

      // Set download headers
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename=report_${analysisId}.json`);

      res.status(200).send(JSON.stringify(report, null, 2));
    } catch (error) {
      logger.error(`Failed to download JSON report: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Download report as CSV
   * GET /api/v1/reports/:analysisId/download/csv
   */
  static async downloadCSV(req, res, next) {
    try {
      const { analysisId } = req.params;

      const report = await ReportService.generateReport(analysisId);

      // Generate CSV from report data
      let csv = 'Category,Key,Value\n';
      
      // Sample info
      csv += `"Sample Info","Filename","${report.sampleInfo.filename}"\n`;
      csv += `"Sample Info","SHA256","${report.sampleInfo.sha256}"\n`;
      csv += `"Sample Info","MD5","${report.sampleInfo.md5}"\n`;
      csv += `"Sample Info","File Size","${report.sampleInfo.fileSize}"\n`;
      csv += `"Sample Info","File Type","${report.sampleInfo.fileType}"\n`;
      csv += `"Sample Info","PE Type","${report.sampleInfo.peType}"\n`;
      csv += `"Sample Info","Architecture","${report.sampleInfo.arch}"\n`;

      // Verdict
      csv += `"Verdict","Classification","${report.finalVerdict.classification}"\n`;
      csv += `"Verdict","Risk Level","${report.finalVerdict.riskLevel}"\n`;
      csv += `"Verdict","Confidence","${report.finalVerdict.confidence}"\n`;

      // Statistics
      csv += `"Statistics","IOCs","${report.summary.statistics.totalIOCs}"\n`;
      csv += `"Statistics","YARA Matches","${report.summary.statistics.yaraMatches}"\n`;
      csv += `"Statistics","Behavioral Findings","${report.summary.statistics.behavioralFindings}"\n`;

      // IOCs
      if (report.iocs.items && report.iocs.items.length > 0) {
        csv += `"IOCs","Count","${report.iocs.items.length}"\n`;
        for (const ioc of report.iocs.items.slice(0, 10)) {
          csv += `"IOC","${ioc.type}","${ioc.value}"\n`;
        }
        if (report.iocs.items.length > 10) {
          csv += `"IOC","...","${report.iocs.items.length - 10} more IOCs"\n`;
        }
      }

      // Recommendations
      if (report.summary.recommendations && report.summary.recommendations.length > 0) {
        for (const rec of report.summary.recommendations) {
          csv += `"Recommendation","","${rec.replace(/"/g, '""')}"\n`;
        }
      }

      // Set download headers
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename=report_${analysisId}.csv`);

      res.status(200).send(csv);
    } catch (error) {
      logger.error(`Failed to download CSV report: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get available report formats
   * GET /api/v1/reports/formats
   */
  static async getFormats(req, res, next) {
    try {
      res.status(200).json({
        success: true,
        data: {
          formats: [
            {
              id: 'json',
              name: 'JSON',
              description: 'Full report in JSON format',
              extension: '.json',
              contentType: 'application/json',
            },
            {
              id: 'csv',
              name: 'CSV',
              description: 'Report data in CSV format (summary only)',
              extension: '.csv',
              contentType: 'text/csv',
            },
            // Future formats
            // {
            //   id: 'pdf',
            //   name: 'PDF',
            //   description: 'Professional PDF report',
            //   extension: '.pdf',
            //   contentType: 'application/pdf',
            // },
            // {
            //   id: 'html',
            //   name: 'HTML',
            //   description: 'Human-readable HTML report',
            //   extension: '.html',
            //   contentType: 'text/html',
            // },
          ],
        },
      });
    } catch (error) {
      logger.error(`Failed to get report formats: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Check if report exists
   * GET /api/v1/reports/:analysisId/exists
   */
  static async reportExists(req, res, next) {
    try {
      const { analysisId } = req.params;

      const exists = await ReportService.hasReport(analysisId);

      res.status(200).json({
        success: true,
        data: { exists },
      });
    } catch (error) {
      logger.error(`Failed to check report existence: ${error.message}`, { error });
      next(error);
    }
  }
}

module.exports = ReportController;