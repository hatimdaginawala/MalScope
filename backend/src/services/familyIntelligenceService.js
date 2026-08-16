const MalwareFamily = require('../models/MalwareFamily');
const MalwareSample = require('../models/MalwareSample');
const IOC = require('../models/IOC');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class FamilyIntelligenceService {
  /**
   * Create or update a malware family
   */
  static async createFamily(name, data = {}) {
    try {
      // Check if family already exists
      let family = await MalwareFamily.findOne({ name: { $regex: new RegExp(name, 'i') } });

      if (family) {
        // Update existing
        if (data.aliases) {
          family.aliases = [...new Set([...family.aliases, ...data.aliases])];
        }
        if (data.characteristics) {
          family.characteristics = { ...family.characteristics, ...data.characteristics };
        }
        if (data.threatIntel) {
          family.threatIntel = { ...family.threatIntel, ...data.threatIntel };
        }
        if (data.tags) {
          family.tags = [...new Set([...family.tags, ...data.tags])];
        }
        await family.save();
        logger.info(`Updated malware family: ${name}`);
      } else {
        // Create new
        family = new MalwareFamily({
          name: name,
          aliases: data.aliases || [],
          source: data.source || 'manual',
          characteristics: data.characteristics || {},
          threatIntel: data.threatIntel || {},
          tags: data.tags || [],
          isActive: true,
          metadata: data.metadata || {},
        });
        await family.save();
        logger.info(`Created malware family: ${name}`);
      }

      return family;
    } catch (error) {
      logger.error(`Failed to create/update family: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Add sample to a family
   */
  static async addSampleToFamily(familyId, sampleId, confidence = 0.5) {
    try {
      const family = await MalwareFamily.findById(familyId);
      if (!family) {
        throw new ApiError(404, 'Family not found');
      }

      const sample = await MalwareSample.findById(sampleId);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      await family.addSample(sampleId, confidence);
      await family.updateStats();

      logger.info(`Sample ${sampleId} added to family: ${family.name}`);
      return family;
    } catch (error) {
      logger.error(`Failed to add sample to family: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Remove sample from a family
   */
  static async removeSampleFromFamily(familyId, sampleId) {
    try {
      const family = await MalwareFamily.findById(familyId);
      if (!family) {
        throw new ApiError(404, 'Family not found');
      }

      await family.removeSample(sampleId);
      await family.updateStats();

      logger.info(`Sample ${sampleId} removed from family: ${family.name}`);
      return family;
    } catch (error) {
      logger.error(`Failed to remove sample from family: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get family by ID
   */
  static async getFamilyById(familyId) {
    try {
      const family = await MalwareFamily.findById(familyId)
        .populate('samples.sample', 'filename sha256 fileSize status')
        .lean();

      if (!family) {
        throw new ApiError(404, 'Family not found');
      }

      return family;
    } catch (error) {
      logger.error(`Failed to get family: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get family by name
   */
  static async getFamilyByName(name) {
    try {
      const family = await MalwareFamily.findByName(name)
        .populate('samples.sample', 'filename sha256 fileSize status')
        .lean();

      return family;
    } catch (error) {
      logger.error(`Failed to get family by name: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get family for a sample
   */
  static async getFamilyForSample(sampleId) {
    try {
      const family = await MalwareFamily.getForSample(sampleId)
        .populate('samples.sample', 'filename sha256 fileSize status')
        .lean();

      return family;
    } catch (error) {
      logger.error(`Failed to get family for sample: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * List all families with pagination
   */
  static async listFamilies(page = 1, limit = 20, filters = {}) {
    try {
      const skip = (page - 1) * limit;

      const query = { isActive: true };
      if (filters.search) {
        query.$or = [
          { name: { $regex: filters.search, $options: 'i' } },
          { aliases: { $regex: filters.search, $options: 'i' } },
        ];
      }
      if (filters.riskLevel) {
        query['threatIntel.riskLevel'] = filters.riskLevel;
      }

      const [families, total] = await Promise.all([
        MalwareFamily.find(query)
          .sort({ 'stats.sampleCount': -1 })
          .skip(skip)
          .limit(limit)
          .lean(),
        MalwareFamily.countDocuments(query),
      ]);

      return {
        families,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      logger.error(`Failed to list families: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get top families by sample count
   */
  static async getTopFamilies(limit = 10) {
    try {
      return await MalwareFamily.getTopFamilies(limit);
    } catch (error) {
      logger.error(`Failed to get top families: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Infer family for a sample based on static analysis
   */
  static async inferFamily(sampleId, staticData) {
    try {
      const evidence = [];
      let bestMatch = null;
      let bestScore = 0;

      // Check if sample already has a family
      const existing = await MalwareFamily.getForSample(sampleId);
      if (existing) {
        return existing;
      }

      // Get all families
      const families = await MalwareFamily.find({ isActive: true }).lean();

      for (const family of families) {
        let score = 0;
        const matchedEvidence = [];

        // Check YARA overlap
        if (family.characteristics?.commonYara) {
          const yaraMatches = staticData.yaraMatches || [];
          for (const yara of family.characteristics.commonYara) {
            if (yaraMatches.some(m => m.ruleName === yara)) {
              score += 0.3;
              matchedEvidence.push(`YARA rule: ${yara}`);
            }
          }
        }

        // Check import overlap
        if (family.characteristics?.commonImports) {
          const imports = staticData.imports || [];
          const funcs = new Set();
          for (const imp of imports) {
            for (const func of imp.functions || []) {
              funcs.add(func);
            }
          }
          for (const imp of family.characteristics.commonImports) {
            if (funcs.has(imp)) {
              score += 0.2;
              matchedEvidence.push(`Import: ${imp}`);
            }
          }
        }

        // Check IOC overlap
        if (family.characteristics?.commonIOCs) {
          const sampleIOCs = await IOC.find({ sample: sampleId }).lean();
          const iocValues = new Set(sampleIOCs.map(i => i.value));
          for (const ioc of family.characteristics.commonIOCs) {
            if (iocValues.has(ioc)) {
              score += 0.2;
              matchedEvidence.push(`IOC: ${ioc}`);
            }
          }
        }

        // Check behavior overlap
        if (family.characteristics?.commonBehaviors) {
          const behaviors = staticData.findings || [];
          for (const behavior of family.characteristics.commonBehaviors) {
            if (behaviors.some(b => b.description.includes(behavior))) {
              score += 0.3;
              matchedEvidence.push(`Behavior: ${behavior}`);
            }
          }
        }

        if (score > bestScore) {
          bestScore = score;
          bestMatch = {
            family,
            score,
            evidence: matchedEvidence.slice(0, 5),
          };
        }
      }

      if (bestMatch && bestMatch.score > 1.0) {
        // Add sample to family
        const confidence = Math.min(bestMatch.score / 2, 1.0);
        await this.addSampleToFamily(bestMatch.family._id, sampleId, confidence);

        logger.info(`Sample ${sampleId} assigned to family: ${bestMatch.family.name} (confidence: ${confidence})`);
        return {
          family: bestMatch.family,
          confidence,
          evidence: bestMatch.evidence,
        };
      }

      return null;
    } catch (error) {
      logger.error(`Failed to infer family: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Delete a family
   */
  static async deleteFamily(familyId) {
    try {
      const family = await MalwareFamily.findById(familyId);
      if (!family) {
        throw new ApiError(404, 'Family not found');
      }

      await family.deleteOne();
      logger.info(`Family deleted: ${familyId}`);
      return { success: true };
    } catch (error) {
      logger.error(`Failed to delete family: ${error.message}`, { error });
      throw error;
    }
  }
}

module.exports = FamilyIntelligenceService;