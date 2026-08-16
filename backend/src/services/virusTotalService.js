const axios = require('axios');
const VirusTotalReport = require('../models/VirusTotalReport');
const logger = require('../utils/logger');
const environment = require('../config/environment');
const { ApiError } = require('../middleware/errorMiddleware');

class VirusTotalService {
  constructor() {
    this.apiKey = environment.vtApiKey;
    this.baseURL = 'https://www.virustotal.com/api/v3';
    this.isEnabled = !!this.apiKey && this.apiKey !== 'ad764f700f897eceef2c3aaab4256752a9619b7a1f11b8daadcc0155d189d9ad';
  }

  /**
   * Check if VirusTotal integration is enabled
   */
  isEnabled() {
    return this.isEnabled;
  }

  /**
   * Get headers for VirusTotal API
   */
  _getHeaders() {
    return {
      'x-apikey': this.apiKey,
      'accept': 'application/json',
    };
  }

  /**
   * Get file report by hash
   */
  async getFileReport(hash, analysisId = null, sampleId = null) {
    try {
      if (!this.isEnabled) {
        logger.warn('VirusTotal API key not configured, skipping enrichment');
        return null;
      }

      // Check if we already have a report for this hash
      if (sampleId) {
        const existing = await VirusTotalReport.findOne({ 
          sample: sampleId,
          'request.hash': hash,
        }).sort({ createdAt: -1 });

        if (existing) {
          // Check if report is still valid (cache for 24 hours)
          const cacheAge = Date.now() - existing.createdAt.getTime();
          if (cacheAge < 24 * 60 * 60 * 1000) {
            logger.info(`Using cached VirusTotal report for ${hash}`);
            return existing;
          }
        }
      }

      // Make API request
      logger.info(`Querying VirusTotal for hash: ${hash}`);
      
      const response = await axios.get(
        `${this.baseURL}/files/${hash}`,
        { headers: this._getHeaders() }
      );

      // Parse and normalize the response
      const report = this._normalizeResponse(response.data, hash, analysisId, sampleId);

      // Store in database
      if (sampleId && analysisId) {
        const saved = await this._saveReport(report);
        return saved;
      }

      return report;
    } catch (error) {
      if (error.response) {
        // VirusTotal API error
        const status = error.response.status;
        if (status === 404) {
          logger.info(`File not found in VirusTotal: ${hash}`);
          return null;
        } else if (status === 429) {
          logger.warn('VirusTotal rate limit exceeded');
          throw new ApiError(429, 'VirusTotal rate limit exceeded');
        } else {
          logger.error(`VirusTotal API error: ${status}`, { error: error.response.data });
          throw new ApiError(status, `VirusTotal API error: ${error.response.data.error?.message || 'Unknown error'}`);
        }
      } else if (error.request) {
        // Network error
        logger.error('VirusTotal network error', { error: error.message });
        throw new ApiError(503, 'VirusTotal service unavailable');
      } else {
        // Other errors
        logger.error('VirusTotal error', { error: error.message });
        throw error;
      }
    }
  }

  /**
   * Normalize VirusTotal response
   */
  _normalizeResponse(data, hash, analysisId = null, sampleId = null) {
    const attributes = data.data.attributes || {};

    // Calculate detection statistics
    const stats = attributes.last_analysis_stats || {};
    const totalDetections = Object.values(stats).reduce((a, b) => a + b, 0);

    // Get detection results
    const detections = [];
    const analysisResults = attributes.last_analysis_results || {};
    for (const [engine, result] of Object.entries(analysisResults)) {
      if (result && result.result) {
        detections.push({
          engine: engine,
          detection: result.result,
          version: result.version,
          update: result.update ? new Date(result.update) : null,
          result: result.result,
          method: result.method,
          engineVersion: result.engine_version,
          engineUpdate: result.engine_update ? new Date(result.engine_update) : null,
        });
      }
    }

    // Get threat intelligence
    const threatNames = [];
    const families = [];
    const tags = [];

    if (attributes.popularity_rank) {
      // Handle threat names from various sources
      if (attributes.names) {
        // File names from VirusTotal
      }
    }

    // Build the normalized report
    return {
      sample: sampleId,
      analysis: analysisId,
      request: {
        hash: hash,
        timestamp: new Date(),
      },
      stats: {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        undetected: stats.undetected || 0,
        harmless: stats.harmless || 0,
        timeout: stats.timeout || 0,
        total: totalDetections,
      },
      detections: detections,
      threatIntelligence: {
        threatNames: threatNames,
        families: families,
        tags: tags,
        categories: {},
      },
      fileInfo: {
        sha256: attributes.sha256 || hash,
        md5: attributes.md5 || '',
        sha1: attributes.sha1 || '',
        fileSize: attributes.size || 0,
        fileType: attributes.type_description || '',
        magic: attributes.magic || '',
        names: attributes.names || [],
        signatures: attributes.signature_info ? Object.values(attributes.signature_info) : [],
        popularity: {
          rank: attributes.popularity_rank || 0,
          votes: attributes.times_submitted || 0,
        },
      },
      reputation: {
        score: this._calculateReputation(stats),
        positives: stats.malicious || 0,
        total: totalDetections,
      },
      related: {
        samples: [],
        domains: [],
        ips: [],
      },
      rawResponse: data.data,
      fetchedAt: new Date(),
      version: '3.0',
      isCached: false,
    };
  }

  /**
   * Calculate reputation score
   */
  _calculateReputation(stats) {
    const total = Object.values(stats).reduce((a, b) => a + b, 0);
    if (total === 0) return 0;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmful = malicious + suspicious;
    return Math.round((harmful / total) * 100);
  }

  /**
   * Save VirusTotal report to database
   */
  async _saveReport(report) {
    try {
      const vtReport = new VirusTotalReport(report);
      await vtReport.save();
      return vtReport;
    } catch (error) {
      logger.error('Failed to save VirusTotal report', { error: error.message });
      throw error;
    }
  }

  /**
   * Get VirusTotal report from database
   */
  async getReportFromDB(sampleId) {
    try {
      const report = await VirusTotalReport.findOne({ sample: sampleId })
        .sort({ createdAt: -1 })
        .lean();

      return report;
    } catch (error) {
      logger.error('Failed to get VirusTotal report from DB', { error: error.message });
      return null;
    }
  }

  /**
   * Enrich analysis with VirusTotal intelligence
   */
  async enrichAnalysis(analysisId, sampleId, hash) {
    try {
      if (!this.isEnabled) {
        logger.info('VirusTotal enrichment skipped: API key not configured');
        return null;
      }

      // Check if already enriched
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (analysis && analysis.virusTotalReport) {
        logger.info(`Analysis ${analysisId} already has VirusTotal enrichment`);
        const existing = await VirusTotalReport.findById(analysis.virusTotalReport);
        if (existing) return existing;
      }

      // Get report
      const report = await this.getFileReport(hash, analysisId, sampleId);

      if (report) {
        logger.info(`VirusTotal enrichment completed for ${hash}`);
        
        // Update analysis with report reference
        if (analysisId) {
          const analysis = await AnalysisService.getAnalysisById(analysisId);
          if (analysis) {
            analysis.virusTotalReport = report._id;
            await analysis.save();
          }
        }

        return report;
      }

      return null;
    } catch (error) {
      logger.error(`VirusTotal enrichment failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get detection summary
   */
  getDetectionSummary(report) {
    if (!report) return null;

    return {
      malicious: report.stats?.malicious || 0,
      suspicious: report.stats?.suspicious || 0,
      total: report.stats?.total || 0,
      detectionRatio: `${report.stats?.malicious || 0}/${report.stats?.total || 0}`,
      isMalicious: (report.stats?.malicious || 0) > 0,
      score: report.reputation?.score || 0,
    };
  }
}

module.exports = new VirusTotalService();