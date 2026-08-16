const ConfigurationIndicator = require('../models/ConfigurationIndicator');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class ConfigurationService {
  /**
   * Save configuration indicators from analysis
   */
  static async saveIndicators(sampleId, analysisId, indicators, sourceType = 'string') {
    try {
      const saved = [];
      
      for (const indicator of indicators) {
        // Normalize the value
        const normalizedValue = (indicator.value || '').toLowerCase().trim();
        if (!normalizedValue) continue;

        // Check if indicator already exists
        const existing = await ConfigurationIndicator.findOne({
          sample: sampleId,
          type: indicator.type,
          normalizedValue: normalizedValue,
        });

        if (existing) {
          // Update existing
          existing.lastSeen = new Date();
          existing.confidence = Math.max(existing.confidence, indicator.confidence || 0.5);
          if (indicator.evidence) {
            existing.evidence = indicator.evidence;
          }
          await existing.save();
          saved.push(existing);
        } else {
          // Create new
          const newIndicator = new ConfigurationIndicator({
            type: indicator.type,
            value: indicator.value,
            normalizedValue: normalizedValue,
            sourceType: sourceType,
            confidence: indicator.confidence || 0.5,
            severity: indicator.severity || 'medium',
            sample: sampleId,
            analysis: analysisId,
            evidence: indicator.evidence || '',
            context: indicator.context || {},
            tags: indicator.tags || [],
            firstSeen: new Date(),
            lastSeen: new Date(),
          });
          await newIndicator.save();
          saved.push(newIndicator);
        }
      }

      logger.info(`Saved ${saved.length} configuration indicators for sample ${sampleId}`);
      return saved;
    } catch (error) {
      logger.error(`Failed to save configuration indicators: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get configuration indicators for a sample
   */
  static async getForSample(sampleId, page = 1, limit = 50) {
    try {
      const skip = (page - 1) * limit;

      const [indicators, total] = await Promise.all([
        ConfigurationIndicator.find({ sample: sampleId })
          .sort({ confidence: -1, severity: -1, createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        ConfigurationIndicator.countDocuments({ sample: sampleId }),
      ]);

      return {
        indicators,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      logger.error(`Failed to get configuration indicators: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get high-confidence indicators for a sample
   */
  static async getHighConfidence(sampleId, minConfidence = 0.7) {
    try {
      return await ConfigurationIndicator.find({
        sample: sampleId,
        confidence: { $gte: minConfidence },
      })
        .sort({ confidence: -1 })
        .lean();
    } catch (error) {
      logger.error(`Failed to get high-confidence indicators: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Search configuration indicators by value
   */
  static async search(query, page = 1, limit = 50) {
    try {
      const skip = (page - 1) * limit;
      const searchRegex = new RegExp(query, 'i');

      const filter = {
        $or: [
          { value: searchRegex },
          { normalizedValue: searchRegex },
          { evidence: searchRegex },
        ],
      };

      const [indicators, total] = await Promise.all([
        ConfigurationIndicator.find(filter)
          .populate('sample', 'filename sha256 status')
          .sort({ confidence: -1, severity: -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        ConfigurationIndicator.countDocuments(filter),
      ]);

      return {
        indicators,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      logger.error(`Failed to search configuration indicators: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get statistics about configuration indicators
   */
  static async getStats() {
    try {
      const [total, byType, bySeverity] = await Promise.all([
        ConfigurationIndicator.countDocuments(),
        ConfigurationIndicator.aggregate([
          { $group: { _id: '$type', count: { $sum: 1 } } },
          { $sort: { count: -1 } },
        ]),
        ConfigurationIndicator.aggregate([
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
      logger.error(`Failed to get configuration stats: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Delete a configuration indicator
   */
  static async deleteIndicator(indicatorId) {
    try {
      const indicator = await ConfigurationIndicator.findById(indicatorId);
      if (!indicator) {
        throw new ApiError(404, 'Configuration indicator not found');
      }

      await indicator.deleteOne();
      logger.info(`Configuration indicator deleted: ${indicatorId}`);
      return { success: true };
    } catch (error) {
      logger.error(`Failed to delete configuration indicator: ${error.message}`, { error });
      throw error;
    }
  }
}

module.exports = ConfigurationService;