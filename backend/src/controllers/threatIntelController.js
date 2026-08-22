const IOCService = require('../services/iocService');
const ConfigurationService = require('../services/configurationService');
const SimilarityService = require('../services/similarityService');
const FamilyIntelligenceService = require('../services/familyIntelligenceService');
const VirusTotalService = require('../services/virusTotalService');
const SampleService = require('../services/sampleService');
const MalwareSample = require('../models/MalwareSample');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class ThreatIntelController {
  // ===== Existing IOC methods =====
  static async listIOCs(req, res, next) {
    try {
      const { page, limit, search } = req.query;
      const result = await IOCService.searchIOCs(search || null, parseInt(page) || 1, parseInt(limit) || 50);
      res.status(200).json({ success: true, data: result.iocs, pagination: result.pagination });
    } catch (error) {
      logger.error(`Failed to list IOCs: ${error.message}`, { error });
      next(error);
    }
  }

  static async searchIOCs(req, res, next) {
    try {
      const { query, page, limit } = req.query;
      if (!query) {
        throw new ApiError(400, 'Search query is required');
      }
      const result = await IOCService.searchIOCs(query, parseInt(page) || 1, parseInt(limit) || 50);
      res.status(200).json({ success: true, data: result.iocs, pagination: result.pagination });
    } catch (error) {
      logger.error(`Failed to search IOCs: ${error.message}`, { error });
      next(error);
    }
  }

  static async getIOCsForSample(req, res, next) {
    try {
      const { sampleId } = req.params;
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 50;
      const result = await IOCService.getIOCsForSample(sampleId, page, limit);
      res.status(200).json({ success: true, data: result.iocs, pagination: result.pagination });
    } catch (error) {
      logger.error(`Failed to get IOCs for sample: ${error.message}`, { error });
      next(error);
    }
  }

  static async getIOC(req, res, next) {
    try {
      const { id } = req.params;
      const IOC = require('../models/IOC');
      const ioc = await IOC.findById(id).populate('sample', 'filename sha256 status').lean();
      if (!ioc) throw new ApiError(404, 'IOC not found');
      res.status(200).json({ success: true, data: ioc });
    } catch (error) {
      logger.error(`Failed to get IOC: ${error.message}`, { error });
      next(error);
    }
  }

  static async deleteIOC(req, res, next) {
    try {
      const { id } = req.params;
      await IOCService.deleteIOC(id);
      res.status(200).json({ success: true, message: 'IOC deleted successfully' });
    } catch (error) {
      logger.error(`Failed to delete IOC: ${error.message}`, { error });
      next(error);
    }
  }

  static async updateIOC(req, res, next) {
    try {
      const { id } = req.params;
      const { confidence, severity, notes, tags, isActive } = req.body;
      const IOC = require('../models/IOC');
      const ioc = await IOC.findById(id);
      if (!ioc) throw new ApiError(404, 'IOC not found');
      if (confidence !== undefined) ioc.confidence = confidence;
      if (severity) ioc.severity = severity;
      if (notes !== undefined) ioc.notes = notes;
      if (tags) ioc.tags = tags;
      if (isActive !== undefined) ioc.isActive = isActive;
      await ioc.save();
      res.status(200).json({ success: true, message: 'IOC updated successfully', data: ioc });
    } catch (error) {
      logger.error(`Failed to update IOC: ${error.message}`, { error });
      next(error);
    }
  }

  static async getIOCStats(req, res, next) {
    try {
      const stats = await IOCService.getStats();
      res.status(200).json({ success: true, data: stats });
    } catch (error) {
      logger.error(`Failed to get IOC stats: ${error.message}`, { error });
      next(error);
    }
  }

  // ===== NEW: Configuration Indicator methods =====
  static async getConfigIndicators(req, res, next) {
    try {
      const { sampleId } = req.params;
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 50;
      const result = await ConfigurationService.getForSample(sampleId, page, limit);
      res.status(200).json({ success: true, data: result.indicators, pagination: result.pagination });
    } catch (error) {
      logger.error(`Failed to get config indicators: ${error.message}`, { error });
      next(error);
    }
  }

  static async searchConfigIndicators(req, res, next) {
    try {
      const { query, page, limit } = req.query;
      if (!query) {
        throw new ApiError(400, 'Search query is required');
      }
      const result = await ConfigurationService.search(query, parseInt(page) || 1, parseInt(limit) || 50);
      res.status(200).json({ success: true, data: result.indicators, pagination: result.pagination });
    } catch (error) {
      logger.error(`Failed to search config indicators: ${error.message}`, { error });
      next(error);
    }
  }

  static async getConfigStats(req, res, next) {
    try {
      const stats = await ConfigurationService.getStats();
      res.status(200).json({ success: true, data: stats });
    } catch (error) {
      logger.error(`Failed to get config stats: ${error.message}`, { error });
      next(error);
    }
  }

  static async deleteConfigIndicator(req, res, next) {
    try {
      const { id } = req.params;
      await ConfigurationService.deleteIndicator(id);
      res.status(200).json({ success: true, message: 'Configuration indicator deleted successfully' });
    } catch (error) {
      logger.error(`Failed to delete config indicator: ${error.message}`, { error });
      next(error);
    }
  }

  // ===== NEW: Similarity methods =====
  static async getSimilarityResults(req, res, next) {
    try {
      const { sampleId } = req.params;
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 20;
      const result = await SimilarityService.getForSample(sampleId, page, limit);
      res.status(200).json({ success: true, data: result.results, pagination: result.pagination });
    } catch (error) {
      logger.error(`Failed to get similarity results: ${error.message}`, { error });
      next(error);
    }
  }

  static async getRelatedSamples(req, res, next) {
    try {
      const { sampleId } = req.params;
      const minScore = parseFloat(req.query.minScore) || 0.5;
      const related = await SimilarityService.getRelatedSamples(sampleId, minScore);
      res.status(200).json({ success: true, data: related });
    } catch (error) {
      logger.error(`Failed to get related samples: ${error.message}`, { error });
      next(error);
    }
  }

  // ===== NEW: Malware Family methods =====
  static async listFamilies(req, res, next) {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 20;
      const filters = {
        search: req.query.search,
        riskLevel: req.query.riskLevel,
      };
      const result = await FamilyIntelligenceService.listFamilies(page, limit, filters);
      res.status(200).json({ success: true, data: result.families, pagination: result.pagination });
    } catch (error) {
      logger.error(`Failed to list families: ${error.message}`, { error });
      next(error);
    }
  }

  static async getTopFamilies(req, res, next) {
    try {
      const limit = parseInt(req.query.limit) || 10;
      const families = await FamilyIntelligenceService.getTopFamilies(limit);
      res.status(200).json({ success: true, data: families });
    } catch (error) {
      logger.error(`Failed to get top families: ${error.message}`, { error });
      next(error);
    }
  }

  static async getFamilyById(req, res, next) {
    try {
      const { id } = req.params;
      const family = await FamilyIntelligenceService.getFamilyById(id);
      res.status(200).json({ success: true, data: family });
    } catch (error) {
      logger.error(`Failed to get family: ${error.message}`, { error });
      next(error);
    }
  }

  static async getFamilyByName(req, res, next) {
    try {
      const { name } = req.params;
      const family = await FamilyIntelligenceService.getFamilyByName(name);
      if (!family) {
        throw new ApiError(404, 'Family not found');
      }
      res.status(200).json({ success: true, data: family });
    } catch (error) {
      logger.error(`Failed to get family by name: ${error.message}`, { error });
      next(error);
    }
  }

  static async getFamilyForSample(req, res, next) {
    try {
      const { sampleId } = req.params;
      const family = await FamilyIntelligenceService.getFamilyForSample(sampleId);
      res.status(200).json({ success: true, data: family });
    } catch (error) {
      logger.error(`Failed to get family for sample: ${error.message}`, { error });
      next(error);
    }
  }

  static async createFamily(req, res, next) {
    try {
      const { name, aliases, characteristics, threatIntel, tags, source, metadata } = req.body;
      if (!name) {
        throw new ApiError(400, 'Family name is required');
      }
      const family = await FamilyIntelligenceService.createFamily(name, {
        aliases,
        characteristics,
        threatIntel,
        tags,
        source,
        metadata,
      });
      res.status(201).json({ success: true, message: 'Family created successfully', data: family });
    } catch (error) {
      logger.error(`Failed to create family: ${error.message}`, { error });
      next(error);
    }
  }

  static async addSampleToFamily(req, res, next) {
    try {
      const { id } = req.params;
      const { sampleId, confidence } = req.body;
      if (!sampleId) {
        throw new ApiError(400, 'Sample ID is required');
      }
      const family = await FamilyIntelligenceService.addSampleToFamily(id, sampleId, confidence || 0.5);
      res.status(200).json({ success: true, message: 'Sample added to family', data: family });
    } catch (error) {
      logger.error(`Failed to add sample to family: ${error.message}`, { error });
      next(error);
    }
  }

  static async removeSampleFromFamily(req, res, next) {
    try {
      const { id, sampleId } = req.params;
      const family = await FamilyIntelligenceService.removeSampleFromFamily(id, sampleId);
      res.status(200).json({ success: true, message: 'Sample removed from family', data: family });
    } catch (error) {
      logger.error(`Failed to remove sample from family: ${error.message}`, { error });
      next(error);
    }
  }

  static async deleteFamily(req, res, next) {
    try {
      const { id } = req.params;
      await FamilyIntelligenceService.deleteFamily(id);
      res.status(200).json({ success: true, message: 'Family deleted successfully' });
    } catch (error) {
      logger.error(`Failed to delete family: ${error.message}`, { error });
      next(error);
    }
  }

  // ===== Existing VirusTotal methods =====
  static async lookupVT(req, res, next) {
    try {
      const { hash } = req.params;
      if (!VirusTotalService.isEnabled()) {
        throw new ApiError(503, 'VirusTotal service is not configured');
      }
      const report = await VirusTotalService.getFileReport(hash);
      if (!report) {
        return res.status(404).json({ success: true, message: 'File not found in VirusTotal', data: null });
      }
      res.status(200).json({ success: true, data: report });
    } catch (error) {
      logger.error(`VirusTotal lookup failed: ${error.message}`, { error });
      next(error);
    }
  }

  static async getRelatedByIOC(req, res, next) {
    try {
      const { type, value } = req.params;
      const IOC = require('../models/IOC');
      const iocs = await IOC.find({ type, normalizedValue: value.toLowerCase() })
        .populate('sample', 'filename sha256 status fileType');
      const samples = iocs
        .filter(ioc => ioc.sample)
        .map(ioc => ioc.sample)
        .filter((sample, index, self) =>
          index === self.findIndex(s => s._id.toString() === sample._id.toString())
        );
      res.status(200).json({ success: true, data: { iocs: iocs.length, samples } });
    } catch (error) {
      logger.error(`Failed to get related samples: ${error.message}`, { error });
      next(error);
    }
  }

  static async getSummary(req, res, next) {
    try {
      const [iocStats, sampleCount, familyStats] = await Promise.all([
        IOCService.getStats(),
        MalwareSample.countDocuments(),
        FamilyIntelligenceService.getTopFamilies(5),
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
          samples: { total: sampleCount, malicious, suspicious },
          topFamilies: familyStats,
        },
      });
    } catch (error) {
      logger.error(`Failed to get threat intel summary: ${error.message}`, { error });
      next(error);
    }
  }
}

// Alias for backward compatibility
ThreatIntelController.getRelatedSamples = ThreatIntelController.getRelatedByIOC;

module.exports = ThreatIntelController;