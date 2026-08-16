const IOC = require('../models/IOC');
const MalwareSample = require('../models/MalwareSample');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class IOCService {
  /**
   * Extract IOCs from analysis results
   */
  static async extractIOCs(analysisId, sampleId, sources) {
    try {
      const iocs = [];
      const seen = new Set();

      // Extract from static analysis
      if (sources.static) {
        const staticIOCs = await this._extractFromStatic(sources.static, sampleId, analysisId);
        for (const ioc of staticIOCs) {
          const key = `${ioc.type}:${ioc.normalizedValue}`;
          if (!seen.has(key)) {
            seen.add(key);
            iocs.push(ioc);
          }
        }
      }

      // Extract from dynamic analysis
      if (sources.dynamic) {
        const dynamicIOCs = await this._extractFromDynamic(sources.dynamic, sampleId, analysisId);
        for (const ioc of dynamicIOCs) {
          const key = `${ioc.type}:${ioc.normalizedValue}`;
          if (!seen.has(key)) {
            seen.add(key);
            iocs.push(ioc);
          }
        }
      }

      // Extract from VirusTotal
      if (sources.virustotal) {
        const vtIOCs = await this._extractFromVirusTotal(sources.virustotal, sampleId, analysisId);
        for (const ioc of vtIOCs) {
          const key = `${ioc.type}:${ioc.normalizedValue}`;
          if (!seen.has(key)) {
            seen.add(key);
            iocs.push(ioc);
          }
        }
      }

      // Save IOCs to database
      const savedIOCs = [];
      for (const ioc of iocs) {
        // Check if IOC already exists for this sample
        const existing = await IOC.findOne({
          sample: sampleId,
          type: ioc.type,
          normalizedValue: ioc.normalizedValue,
        });

        if (existing) {
          // Update existing
          existing.lastSeen = new Date();
          existing.confidence = Math.max(existing.confidence, ioc.confidence || 0.5);
          await existing.save();
          savedIOCs.push(existing);
        } else {
          const newIOC = new IOC(ioc);
          await newIOC.save();
          savedIOCs.push(newIOC);
        }
      }

      logger.info(`Extracted ${savedIOCs.length} IOCs for sample ${sampleId}`);
      return savedIOCs;
    } catch (error) {
      logger.error(`IOC extraction failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Extract IOCs from static analysis
   */
  static async _extractFromStatic(staticData, sampleId, analysisId) {
    const iocs = [];

    if (!staticData) return iocs;

    // Extract hashes
    if (staticData.fileInfo) {
      const fileInfo = staticData.fileInfo;
      if (fileInfo.sha256) {
        iocs.push({
          type: 'sha256',
          value: fileInfo.sha256,
          normalizedValue: fileInfo.sha256.toLowerCase(),
          source: 'static_analysis',
          sample: sampleId,
          analysis: analysisId,
          confidence: 1.0,
          severity: 'low',
          tags: ['file_hash'],
        });
      }
      if (fileInfo.md5) {
        iocs.push({
          type: 'md5',
          value: fileInfo.md5,
          normalizedValue: fileInfo.md5.toLowerCase(),
          source: 'static_analysis',
          sample: sampleId,
          analysis: analysisId,
          confidence: 1.0,
          severity: 'low',
          tags: ['file_hash'],
        });
      }
    }

    // Extract IPs from strings
    if (staticData.strings && staticData.strings.ascii) {
      const ips = this._extractIPs(staticData.strings.ascii);
      for (const ip of ips) {
        iocs.push({
          type: 'ip',
          value: ip,
          normalizedValue: ip,
          source: 'static_analysis',
          sample: sampleId,
          analysis: analysisId,
          confidence: 0.6,
          severity: 'medium',
          tags: ['network_indicator'],
          context: { source: 'string_analysis' },
        });
      }

      // Extract domains
      const domains = this._extractDomains(staticData.strings.ascii);
      for (const domain of domains) {
        iocs.push({
          type: 'domain',
          value: domain,
          normalizedValue: domain.toLowerCase(),
          source: 'static_analysis',
          sample: sampleId,
          analysis: analysisId,
          confidence: 0.5,
          severity: 'medium',
          tags: ['network_indicator'],
          context: { source: 'string_analysis' },
        });
      }

      // Extract URLs
      const urls = this._extractURLs(staticData.strings.ascii);
      for (const url of urls) {
        iocs.push({
          type: 'url',
          value: url,
          normalizedValue: url.toLowerCase(),
          source: 'static_analysis',
          sample: sampleId,
          analysis: analysisId,
          confidence: 0.5,
          severity: 'medium',
          tags: ['network_indicator'],
          context: { source: 'string_analysis' },
        });
      }
    }

    // Extract from YARA matches
    if (staticData.yaraMatches) {
      for (const match of staticData.yaraMatches) {
        if (match.ruleName) {
          iocs.push({
            type: 'other',
            value: `YARA:${match.ruleName}`,
            normalizedValue: `yara:${match.ruleName.toLowerCase()}`,
            source: 'static_analysis',
            sample: sampleId,
            analysis: analysisId,
            confidence: match.ruleName.includes('suspicious') ? 0.7 : 0.5,
            severity: match.ruleName.includes('malware') ? 'high' : 'medium',
            tags: ['yara_rule'],
            context: { yara_rule: match },
          });
        }
      }
    }

    return iocs;
  }

  /**
   * Extract IOCs from dynamic analysis
   */
  static async _extractFromDynamic(dynamicData, sampleId, analysisId) {
    const iocs = [];

    if (!dynamicData) return iocs;

    // Extract network IOCs
    if (dynamicData.networkEvents) {
      for (const event of dynamicData.networkEvents) {
        if (event.destinationIp && event.destinationIp !== '0.0.0.0') {
          iocs.push({
            type: 'ip',
            value: event.destinationIp,
            normalizedValue: event.destinationIp,
            source: 'dynamic_analysis',
            sample: sampleId,
            analysis: analysisId,
            confidence: 0.8,
            severity: 'high',
            tags: ['network_connection'],
            context: {
              port: event.destinationPort,
              protocol: event.protocol,
              process: event.processName,
            },
          });
        }

        if (event.hostname) {
          iocs.push({
            type: 'domain',
            value: event.hostname,
            normalizedValue: event.hostname.toLowerCase(),
            source: 'dynamic_analysis',
            sample: sampleId,
            analysis: analysisId,
            confidence: 0.8,
            severity: 'high',
            tags: ['dns_query'],
            context: {
              process: event.processName,
            },
          });
        }
      }
    }

    // Extract file paths
    if (dynamicData.fileEvents) {
      for (const event of dynamicData.fileEvents) {
        if (event.path && event.operation !== 'read') {
          iocs.push({
            type: 'file_path',
            value: event.path,
            normalizedValue: event.path.toLowerCase(),
            source: 'dynamic_analysis',
            sample: sampleId,
            analysis: analysisId,
            confidence: 0.6,
            severity: event.operation === 'create' ? 'medium' : 'low',
            tags: ['file_activity'],
            context: {
              operation: event.operation,
              process: event.processName,
            },
          });
        }
      }
    }

    // Extract registry keys
    if (dynamicData.registryEvents) {
      for (const event of dynamicData.registryEvents) {
        if (event.key && (event.operation === 'create' || event.operation === 'modify')) {
          iocs.push({
            type: 'registry_key',
            value: event.key,
            normalizedValue: event.key.toLowerCase(),
            source: 'dynamic_analysis',
            sample: sampleId,
            analysis: analysisId,
            confidence: 0.7,
            severity: 'medium',
            tags: ['registry_activity'],
            context: {
              operation: event.operation,
              process: event.processName,
            },
          });
        }
      }
    }

    return iocs;
  }

  /**
   * Extract IOCs from VirusTotal
   */
  static async _extractFromVirusTotal(vtData, sampleId, analysisId) {
    const iocs = [];

    if (!vtData) return iocs;

    // Extract threat names as IOCs
    if (vtData.threatIntelligence && vtData.threatIntelligence.threatNames) {
      for (const threat of vtData.threatIntelligence.threatNames) {
        iocs.push({
          type: 'other',
          value: `Threat:${threat}`,
          normalizedValue: `threat:${threat.toLowerCase()}`,
          source: 'virustotal',
          sample: sampleId,
          analysis: analysisId,
          confidence: 0.9,
          severity: 'high',
          tags: ['threat_intelligence'],
          malwareFamily: threat,
          threatIntel: {
            isMalicious: true,
            threatTags: vtData.threatIntelligence.tags || [],
          },
        });
      }
    }

    // Extract malware families
    if (vtData.threatIntelligence && vtData.threatIntelligence.families) {
      for (const family of vtData.threatIntelligence.families) {
        iocs.push({
          type: 'other',
          value: `Family:${family}`,
          normalizedValue: `family:${family.toLowerCase()}`,
          source: 'virustotal',
          sample: sampleId,
          analysis: analysisId,
          confidence: 0.9,
          severity: 'high',
          tags: ['malware_family'],
          malwareFamily: family,
        });
      }
    }

    return iocs;
  }

  /**
   * Extract IP addresses from strings
   */
  static _extractIPs(strings) {
    const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const ips = [];
    const seen = new Set();

    for (const str of strings) {
      const matches = str.match(ipPattern);
      if (matches) {
        for (const match of matches) {
          if (!seen.has(match)) {
            seen.add(match);
            ips.push(match);
          }
        }
      }
    }

    return ips;
  }

  /**
   * Extract domains from strings
   */
  static _extractDomains(strings) {
    const domainPattern = /\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b/g;
    const domains = [];
    const seen = new Set();

    for (const str of strings) {
      const matches = str.match(domainPattern);
      if (matches) {
        for (const match of matches) {
          if (!seen.has(match)) {
            seen.add(match);
            domains.push(match);
          }
        }
      }
    }

    return domains;
  }

  /**
   * Extract URLs from strings
   */
  static _extractURLs(strings) {
    const urlPattern = /https?:\/\/[^\s<>"']+/g;
    const urls = [];
    const seen = new Set();

    for (const str of strings) {
      const matches = str.match(urlPattern);
      if (matches) {
        for (const match of matches) {
          if (!seen.has(match)) {
            seen.add(match);
            urls.push(match);
          }
        }
      }
    }

    return urls;
  }

  /**
   * Get IOCs for a sample
   */
  static async getIOCsForSample(sampleId, page = 1, limit = 50) {
    try {
      const skip = (page - 1) * limit;

      const [iocs, total] = await Promise.all([
        IOC.find({ sample: sampleId })
          .sort({ severity: -1, confidence: -1, createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        IOC.countDocuments({ sample: sampleId }),
      ]);

      return {
        iocs,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      logger.error(`Failed to get IOCs: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Search IOCs by value
   */
  static async searchIOCs(query, page = 1, limit = 50) {
    try {
      const skip = (page - 1) * limit;

      // Search by value or normalized value
      const searchRegex = new RegExp(query, 'i');
      const filter = {
        $or: [
          { value: searchRegex },
          { normalizedValue: searchRegex },
        ],
      };

      const [iocs, total] = await Promise.all([
        IOC.find(filter)
          .populate('sample', 'filename sha256 status')
          .sort({ severity: -1, confidence: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        IOC.countDocuments(filter),
      ]);

      return {
        iocs,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      logger.error(`Failed to search IOCs: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get IOC statistics
   */
  static async getStats() {
    try {
      const [total, byType, bySeverity] = await Promise.all([
        IOC.countDocuments(),
        IOC.aggregate([
          { $group: { _id: '$type', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ]),
        IOC.aggregate([
          { $group: { _id: '$severity', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ]),
      ]);

      return {
        total,
        byType: byType.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
        bySeverity: bySeverity.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
      };
    } catch (error) {
      logger.error(`Failed to get IOC stats: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Delete an IOC
   */
  static async deleteIOC(iocId) {
    try {
      const ioc = await IOC.findById(iocId);
      if (!ioc) {
        throw new ApiError(404, 'IOC not found');
      }

      await ioc.deleteOne();
      logger.info(`IOC deleted: ${iocId}`);
      return { success: true };
    } catch (error) {
      logger.error(`Failed to delete IOC: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Update IOC confidence
   */
  static async updateConfidence(iocId, confidence) {
    try {
      const ioc = await IOC.findById(iocId);
      if (!ioc) {
        throw new ApiError(404, 'IOC not found');
      }

      ioc.confidence = confidence;
      await ioc.save();

      return ioc;
    } catch (error) {
      logger.error(`Failed to update IOC confidence: ${error.message}`, { error });
      throw error;
    }
  }
}

module.exports = IOCService;