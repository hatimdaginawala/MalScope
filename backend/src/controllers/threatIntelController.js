const IOCService = require('../services/iocService');
const VirusTotalService = require('../services/virusTotalService');
const SampleService = require('../services/sampleService');
const MalwareSample = require('../models/MalwareSample');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class ThreatIntelController {
  /**
   * Search IOCs
   * GET /api/v1/threat-intel/iocs/search
   */
  static async searchIOCs(req, res, next) {
    try {
      const { query, page, limit } = req.query;

      if (!query) {
        throw new ApiError(400, 'Search query is required');
      }

      const result = await IOCService.searchIOCs(
        query,
        parseInt(page) || 1,
        parseInt(limit) || 50
      );

      res.status(200).json({
        success: true,
        data: result.iocs,
        pagination: result.pagination,
      });
    } catch (error) {
      logger.error(`Failed to search IOCs: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get IOCs for a sample
   * GET /api/v1/threat-intel/samples/:sampleId/iocs
   */
// In the getIOCsForSample method, make sure the response includes the fields
static async getIOCsForSample(req, res, next) {
  try {
    const { sampleId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;

    const result = await IOCService.getIOCsForSample(sampleId, page, limit);

    // Map the response to include type and value
    const mappedIocs = result.iocs.map(ioc => ({
      id: ioc._id,
      type: ioc.type || ioc.iocType,
      value: ioc.value || ioc.iocValue,
      normalizedValue: ioc.normalizedValue,
      confidence: ioc.confidence,
      severity: ioc.severity,
      source: ioc.source,
      tags: ioc.tags,
      firstSeen: ioc.firstSeen,
      lastSeen: ioc.lastSeen,
    }));

    res.status(200).json({
      success: true,
      data: {
        iocs: mappedIocs,
        pagination: result.pagination,
      },
    });
  } catch (error) {
    logger.error(`Failed to get IOCs for sample: ${error.message}`, { error });
    next(error);
  }
}

  /**
   * Get IOC by ID
   * GET /api/v1/threat-intel/iocs/:id
   */
  static async getIOC(req, res, next) {
    try {
      const { id } = req.params;

      const IOC = require('../models/IOC');
      const ioc = await IOC.findById(id)
        .populate('sample', 'filename sha256 status')
        .lean();

      if (!ioc) {
        throw new ApiError(404, 'IOC not found');
      }

      res.status(200).json({
        success: true,
        data: ioc,
      });
    } catch (error) {
      logger.error(`Failed to get IOC: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Delete IOC
   * DELETE /api/v1/threat-intel/iocs/:id
   */
  static async deleteIOC(req, res, next) {
    try {
      const { id } = req.params;

      await IOCService.deleteIOC(id);

      res.status(200).json({
        success: true,
        message: 'IOC deleted successfully',
      });
    } catch (error) {
      logger.error(`Failed to delete IOC: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Update IOC
   * PATCH /api/v1/threat-intel/iocs/:id
   */
  static async updateIOC(req, res, next) {
    try {
      const { id } = req.params;
      const { confidence, severity, notes, tags, isActive } = req.body;

      const IOC = require('../models/IOC');
      const ioc = await IOC.findById(id);

      if (!ioc) {
        throw new ApiError(404, 'IOC not found');
      }

      if (confidence !== undefined) ioc.confidence = confidence;
      if (severity) ioc.severity = severity;
      if (notes !== undefined) ioc.notes = notes;
      if (tags) ioc.tags = tags;
      if (isActive !== undefined) ioc.isActive = isActive;

      await ioc.save();

      res.status(200).json({
        success: true,
        message: 'IOC updated successfully',
        data: ioc,
      });
    } catch (error) {
      logger.error(`Failed to update IOC: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get IOC statistics
   * GET /api/v1/threat-intel/iocs/stats
   */
  static async getIOCStats(req, res, next) {
    try {
      const stats = await IOCService.getStats();

      res.status(200).json({
        success: true,
        data: stats,
      });
    } catch (error) {
      logger.error(`Failed to get IOC stats: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Lookup hash in VirusTotal
   * GET /api/v1/threat-intel/virustotal/:hash
   */
  static async lookupVT(req, res, next) {
    try {
      const { hash } = req.params;

      if (!VirusTotalService.isEnabled()) {
        throw new ApiError(503, 'VirusTotal service is not configured');
      }

      const report = await VirusTotalService.getFileReport(hash);

      if (!report) {
        return res.status(404).json({
          success: true,
          message: 'File not found in VirusTotal',
          data: null,
        });
      }

      res.status(200).json({
        success: true,
        data: report,
      });
    } catch (error) {
      logger.error(`VirusTotal lookup failed: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get related samples by IOC
   * GET /api/v1/threat-intel/related/:type/:value
   */
  static async getRelatedSamples(req, res, next) {
    try {
      const { type, value } = req.params;

      const IOC = require('../models/IOC');
      const iocs = await IOC.find({
        type,
        normalizedValue: value.toLowerCase(),
      }).populate('sample', 'filename sha256 status fileType');

      const samples = iocs
        .filter(ioc => ioc.sample)
        .map(ioc => ioc.sample)
        .filter((sample, index, self) =>
          index === self.findIndex(s => s._id.toString() === sample._id.toString())
        );

      res.status(200).json({
        success: true,
        data: {
          iocs: iocs.length,
          samples: samples,
        },
      });
    } catch (error) {
      logger.error(`Failed to get related samples: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get threat intelligence summary
   * GET /api/v1/threat-intel/summary
   */
  static async getSummary(req, res, next) {
    try {
      const [iocStats, sampleCount] = await Promise.all([
        IOCService.getStats(),
        MalwareSample.countDocuments(),
      ]);

      const ThreatAssessment = require('../models/ThreatAssessment');
      const [malicious, suspicious] = await Promise.all([
        ThreatAssessment.countDocuments({ finalVerdict: 'malicious' }),
        ThreatAssessment.countDocuments({ finalVerdict: 'suspicious' }),
      ]);

      res.status(200).json({
        success: true,
        data: {
          iocs: iocStats,
          samples: {
            total: sampleCount,
            malicious,
            suspicious,
          },
        },
      });
    } catch (error) {
      logger.error(`Failed to get threat intel summary: ${error.message}`, { error });
      next(error);
    }
  }
}

module.exports = ThreatIntelController;