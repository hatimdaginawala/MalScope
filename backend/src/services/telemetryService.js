const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class TelemetryService {
  constructor() {
    this.telemetryDir = path.join(process.cwd(), 'storage', 'telemetry');
  }

  /**
   * Ensure telemetry directory exists
   */
  async _ensureTelemetryDir() {
    await fs.promises.mkdir(this.telemetryDir, { recursive: true });
  }

  /**
   * Save telemetry data
   */
  async saveTelemetry(analysisId, telemetryData) {
    try {
      await this._ensureTelemetryDir();

      const filename = `${analysisId}_${Date.now()}.json`;
      const filePath = path.join(this.telemetryDir, filename);

      // Ensure telemetry data is valid JSON
      const data = typeof telemetryData === 'string' 
        ? telemetryData 
        : JSON.stringify(telemetryData, null, 2);

      await fs.promises.writeFile(filePath, data);

      logger.info(`Telemetry saved: ${filePath}`);
      return { filePath, filename };
    } catch (error) {
      logger.error(`Failed to save telemetry: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Load telemetry data
   */
  async loadTelemetry(filePath) {
    try {
      if (!fs.existsSync(filePath)) {
        throw new ApiError(404, `Telemetry file not found: ${filePath}`);
      }

      const data = await fs.promises.readFile(filePath, 'utf8');
      const telemetry = JSON.parse(data);

      logger.info(`Telemetry loaded: ${filePath}`);
      return telemetry;
    } catch (error) {
      logger.error(`Failed to load telemetry: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get telemetry for analysis
   */
  async getTelemetryForAnalysis(analysisId) {
    try {
      await this._ensureTelemetryDir();

      const files = await fs.promises.readdir(this.telemetryDir);
      const telemetryFiles = files
        .filter(f => f.startsWith(analysisId))
        .sort(); // Get oldest first

      if (telemetryFiles.length === 0) {
        return null;
      }

      // Return the most recent telemetry file
      const latestFile = telemetryFiles[telemetryFiles.length - 1];
      const filePath = path.join(this.telemetryDir, latestFile);

      return await this.loadTelemetry(filePath);
    } catch (error) {
      logger.error(`Failed to get telemetry for analysis: ${error.message}`, { error });
      return null;
    }
  }

  /**
   * Delete telemetry for analysis
   */
  async deleteTelemetry(analysisId) {
    try {
      await this._ensureTelemetryDir();

      const files = await fs.promises.readdir(this.telemetryDir);
      const telemetryFiles = files.filter(f => f.startsWith(analysisId));

      for (const file of telemetryFiles) {
        const filePath = path.join(this.telemetryDir, file);
        await fs.promises.unlink(filePath);
        logger.debug(`Deleted telemetry file: ${filePath}`);
      }

      return { deleted: telemetryFiles.length };
    } catch (error) {
      logger.error(`Failed to delete telemetry: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Normalize telemetry data for analysis
   */
  normalizeTelemetry(rawTelemetry) {
    try {
      // If raw telemetry is not in expected format, try to normalize
      if (typeof rawTelemetry === 'string') {
        rawTelemetry = JSON.parse(rawTelemetry);
      }

      // Basic normalization - ensure consistent structure
      const normalized = {
        processes: rawTelemetry.processes || rawTelemetry.Processes || [],
        fileEvents: rawTelemetry.fileEvents || rawTelemetry.FileEvents || [],
        registryEvents: rawTelemetry.registryEvents || rawTelemetry.RegistryEvents || [],
        networkEvents: rawTelemetry.networkEvents || rawTelemetry.NetworkEvents || [],
        persistence: rawTelemetry.persistence || rawTelemetry.Persistence || [],
        metadata: {
          collectedAt: rawTelemetry.collectedAt || rawTelemetry.CollectedAt || new Date().toISOString(),
          source: rawTelemetry.source || rawTelemetry.Source || 'sysmon',
          analysisId: rawTelemetry.analysisId || rawTelemetry.AnalysisId,
        },
      };

      return normalized;
    } catch (error) {
      logger.error(`Failed to normalize telemetry: ${error.message}`, { error });
      return rawTelemetry; // Return as-is if normalization fails
    }
  }

  /**
   * Validate telemetry data
   */
  validateTelemetry(telemetry) {
    const errors = [];

    if (!telemetry || typeof telemetry !== 'object') {
      errors.push('Telemetry data is not a valid object');
      return errors;
    }

    // Check for required fields
    const requiredFields = ['processes', 'fileEvents', 'registryEvents', 'networkEvents'];
    for (const field of requiredFields) {
      if (!(field in telemetry)) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    // Check data types
    if (telemetry.processes && !Array.isArray(telemetry.processes)) {
      errors.push('processes must be an array');
    }

    if (telemetry.fileEvents && !Array.isArray(telemetry.fileEvents)) {
      errors.push('fileEvents must be an array');
    }

    if (telemetry.registryEvents && !Array.isArray(telemetry.registryEvents)) {
      errors.push('registryEvents must be an array');
    }

    if (telemetry.networkEvents && !Array.isArray(telemetry.networkEvents)) {
      errors.push('networkEvents must be an array');
    }

    return errors;
  }

  /**
   * Get telemetry statistics
   */
  getTelemetryStats(telemetry) {
    const stats = {
      processes: 0,
      fileEvents: 0,
      registryEvents: 0,
      networkEvents: 0,
      persistence: 0,
      totalEvents: 0,
    };

    if (telemetry.processes && Array.isArray(telemetry.processes)) {
      stats.processes = telemetry.processes.length;
    }

    if (telemetry.fileEvents && Array.isArray(telemetry.fileEvents)) {
      stats.fileEvents = telemetry.fileEvents.length;
    }

    if (telemetry.registryEvents && Array.isArray(telemetry.registryEvents)) {
      stats.registryEvents = telemetry.registryEvents.length;
    }

    if (telemetry.networkEvents && Array.isArray(telemetry.networkEvents)) {
      stats.networkEvents = telemetry.networkEvents.length;
    }

    if (telemetry.persistence && Array.isArray(telemetry.persistence)) {
      stats.persistence = telemetry.persistence.length;
    }

    stats.totalEvents = stats.processes + stats.fileEvents + stats.registryEvents + stats.networkEvents;

    return stats;
  }
}

module.exports = new TelemetryService();