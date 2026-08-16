const MalwareSample = require('../models/MalwareSample');
const AnalysisService = require('../services/analysisService');
const ThreatAssessment = require('../models/ThreatAssessment');
const IOCService = require('../services/iocService');
const logger = require('../utils/logger');

class DashboardController {
  /**
   * Get dashboard statistics
   * GET /api/v1/dashboard/stats
   */
  static async getStats(req, res, next) {
    try {
      const [
        sampleStats,
        analysisStats,
        threatStats,
        iocStats,
        recentSamples,
        recentAnalyses,
      ] = await Promise.all([
        this._getSampleStats(),
        AnalysisService.getStats(),
        this._getThreatStats(),
        IOCService.getStats(),
        this._getRecentSamples(10),
        this._getRecentAnalyses(10),
      ]);

      res.status(200).json({
        success: true,
        data: {
          samples: sampleStats,
          analyses: analysisStats,
          threats: threatStats,
          iocs: iocStats,
          recent: {
            samples: recentSamples,
            analyses: recentAnalyses,
          },
          timestamp: new Date().toISOString(),
        },
      });
    } catch (error) {
      logger.error(`Failed to get dashboard stats: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get sample statistics
   */
  static async _getSampleStats() {
    const [total, byStatus, byType] = await Promise.all([
      MalwareSample.countDocuments(),
      MalwareSample.aggregate([
        { $group: { _id: '$status', count: { $sum: 1 } } },
      ]),
      MalwareSample.aggregate([
        { $group: { _id: '$fileType', count: { $sum: 1 } } },
      ]),
    ]);

    return {
      total,
      byStatus: byStatus.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
      byType: byType.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
    };
  }

  /**
   * Get threat statistics
   */
  static async _getThreatStats() {
    const [total, byLevel, byVerdict] = await Promise.all([
      ThreatAssessment.countDocuments(),
      ThreatAssessment.aggregate([
        { $group: { _id: '$level', count: { $sum: 1 } } },
      ]),
      ThreatAssessment.aggregate([
        { $group: { _id: '$finalVerdict', count: { $sum: 1 } } },
      ]),
    ]);

    return {
      total,
      byLevel: byLevel.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
      byVerdict: byVerdict.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
    };
  }

  /**
   * Get recent samples
   */
  static async _getRecentSamples(limit) {
    return MalwareSample.find()
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('submittedBy', 'username')
      .lean();
  }

  /**
   * Get recent analyses
   */
  static async _getRecentAnalyses(limit) {
    return AnalysisService._getRecentAnalyses(limit);
  }

  /**
   * Get dashboard timeline
   * GET /api/v1/dashboard/timeline
   */
  static async getTimeline(req, res, next) {
    try {
      const days = parseInt(req.query.days) || 7;

      const startDate = new Date();
      startDate.setDate(startDate.getDate() - days);

      const analyses = await AnalysisService._getAnalysesInRange(startDate, new Date());

      const timeline = this._buildTimeline(analyses, days);

      res.status(200).json({
        success: true,
        data: {
          timeline,
          startDate,
          endDate: new Date(),
          days,
        },
      });
    } catch (error) {
      logger.error(`Failed to get dashboard timeline: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Build timeline data
   */
  static _buildTimeline(analyses, days) {
    const timeline = [];
    const now = new Date();

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      date.setHours(0, 0, 0, 0);

      const nextDate = new Date(date);
      nextDate.setDate(nextDate.getDate() + 1);

      const dayAnalyses = analyses.filter(a =>
        a.createdAt >= date && a.createdAt < nextDate
      );

      timeline.push({
        date: date.toISOString().split('T')[0],
        total: dayAnalyses.length,
        completed: dayAnalyses.filter(a => a.status === 'completed').length,
        failed: dayAnalyses.filter(a => a.status === 'failed').length,
        malicious: dayAnalyses.filter(a => 
          a.threatAssessment && a.threatAssessment.finalVerdict === 'malicious'
        ).length,
      });
    }

    return timeline;
  }

  /**
   * Get dashboard alerts
   * GET /api/v1/dashboard/alerts
   */
  static async getAlerts(req, res, next) {
    try {
      // Find recent malicious or critical samples
      const alerts = [];

      // Critical threat assessments
      const criticalThreats = await ThreatAssessment.find({
        level: 'critical',
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
      })
        .populate('sample', 'filename sha256')
        .sort({ createdAt: -1 })
        .limit(10);

      for (const threat of criticalThreats) {
        alerts.push({
          type: 'critical_threat',
          severity: 'critical',
          message: `Critical threat detected: ${threat.sample.filename}`,
          timestamp: threat.createdAt,
          data: {
            sampleId: threat.sample._id,
            sha256: threat.sample.sha256,
            score: threat.score,
            level: threat.level,
          },
        });
      }

      // High severity IOCs
      const highIOCs = await IOCService._getRecentHighSeverity(10);
      for (const ioc of highIOCs) {
        alerts.push({
          type: 'high_severity_ioc',
          severity: 'high',
          message: `High-severity IOC detected: ${ioc.type}:${ioc.value}`,
          timestamp: ioc.createdAt,
          data: {
            iocId: ioc._id,
            type: ioc.type,
            value: ioc.value,
            confidence: ioc.confidence,
          },
        });
      }

      res.status(200).json({
        success: true,
        data: {
          alerts: alerts.slice(0, 20),
          total: alerts.length,
        },
      });
    } catch (error) {
      logger.error(`Failed to get dashboard alerts: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get dashboard widgets data
   * GET /api/v1/dashboard/widgets
   */
  static async getWidgets(req, res, next) {
    try {
      const [sampleStats, threatStats, iocStats, recentAlerts] = await Promise.all([
        this._getSampleStats(),
        this._getThreatStats(),
        IOCService.getStats(),
        this._getRecentAlerts(5),
      ]);

      res.status(200).json({
        success: true,
        data: {
          widgets: {
            samples: {
              total: sampleStats.total,
              pending: sampleStats.byStatus.pending || 0,
              completed: sampleStats.byStatus.completed || 0,
              failed: sampleStats.byStatus.failed || 0,
            },
            threats: {
              malicious: threatStats.byVerdict.malicious || 0,
              suspicious: threatStats.byVerdict.suspicious || 0,
              critical: threatStats.byLevel.critical || 0,
              high: threatStats.byLevel.high || 0,
            },
            iocs: {
              total: iocStats.total || 0,
              critical: iocStats.bySeverity.critical || 0,
              high: iocStats.bySeverity.high || 0,
            },
            alerts: recentAlerts,
          },
        },
      });
    } catch (error) {
      logger.error(`Failed to get dashboard widgets: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get recent alerts
   */
  static async _getRecentAlerts(limit) {
    // Get recent critical threats and high IOCs
    const threats = await ThreatAssessment.find({
      level: { $in: ['critical', 'high'] },
    })
      .populate('sample', 'filename')
      .sort({ createdAt: -1 })
      .limit(limit);

    return threats.map(t => ({
      id: t._id,
      type: 'threat_assessment',
      level: t.level,
      message: `${t.level.toUpperCase()} threat: ${t.sample.filename}`,
      timestamp: t.createdAt,
    }));
  }

  /**
   * Get daily summary
   * GET /api/v1/dashboard/daily
   */
  static async getDailySummary(req, res, next) {
    try {
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      const tomorrow = new Date(today);
      tomorrow.setDate(tomorrow.getDate() + 1);

      const [submissions, analyses, threats] = await Promise.all([
        MalwareSample.countDocuments({
          createdAt: { $gte: today, $lt: tomorrow },
        }),
        AnalysisService._getAnalysesInRange(today, tomorrow),
        ThreatAssessment.countDocuments({
          createdAt: { $gte: today, $lt: tomorrow },
          finalVerdict: 'malicious',
        }),
      ]);

      res.status(200).json({
        success: true,
        data: {
          date: today.toISOString().split('T')[0],
          submissions,
          analyses: {
            total: analyses.length,
            completed: analyses.filter(a => a.status === 'completed').length,
            failed: analyses.filter(a => a.status === 'failed').length,
          },
          threats: {
            malicious: threats,
          },
        },
      });
    } catch (error) {
      logger.error(`Failed to get daily summary: ${error.message}`, { error });
      next(error);
    }
  }
}

// Add helper methods to AnalysisService for dashboard
AnalysisService._getRecentAnalyses = async function(limit) {
  return Analysis.find()
    .sort({ createdAt: -1 })
    .limit(limit)
    .populate('sample', 'filename sha256')
    .populate('threatAssessment')
    .lean();
};

AnalysisService._getAnalysesInRange = async function(startDate, endDate) {
  return Analysis.find({
    createdAt: { $gte: startDate, $lt: endDate },
  })
    .populate('threatAssessment')
    .lean();
};

// Add helper method to IOCService
IOCService._getRecentHighSeverity = async function(limit) {
  const IOC = require('../models/IOC');
  return IOC.find({
    severity: { $in: ['critical', 'high'] },
  })
    .sort({ createdAt: -1 })
    .limit(limit)
    .lean();
};

module.exports = DashboardController;