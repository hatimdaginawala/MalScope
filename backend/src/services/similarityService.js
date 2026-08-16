const SimilarityResult = require('../models/SimilarityResult');
const MalwareSample = require('../models/MalwareSample');
const IOC = require('../models/IOC');
const StaticAnalysis = require('../models/StaticAnalysis');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class SimilarityService {
  /**
   * Calculate similarity between two samples
   */
  static async calculateSimilarity(sampleIdA, sampleIdB, analysisId = null) {
    try {
      // Get both samples
      const [sampleA, sampleB] = await Promise.all([
        MalwareSample.findById(sampleIdA).lean(),
        MalwareSample.findById(sampleIdB).lean(),
      ]);

      if (!sampleA || !sampleB) {
        throw new ApiError(404, 'One or both samples not found');
      }

      // Get static analyses
      const [staticA, staticB] = await Promise.all([
        StaticAnalysis.findOne({ sample: sampleIdA }).sort({ createdAt: -1 }).lean(),
        StaticAnalysis.findOne({ sample: sampleIdB }).sort({ createdAt: -1 }).lean(),
      ]);

      // Get IOCs
      const [iocsA, iocsB] = await Promise.all([
        IOC.find({ sample: sampleIdA }).lean(),
        IOC.find({ sample: sampleIdB }).lean(),
      ]);

      // Calculate feature similarities
      const features = {
        imports: this._compareImports(staticA, staticB),
        sections: this._compareSections(staticA, staticB),
        strings: this._compareStrings(staticA, staticB),
        yara: this._compareYara(staticA, staticB),
        iocs: this._compareIOCs(iocsA, iocsB),
        resources: this._compareResources(staticA, staticB),
        entropy: this._compareEntropy(staticA, staticB),
        packer: this._comparePacker(staticA, staticB),
      };

      // Calculate weighted overall score
      const weights = {
        imports: 0.25,
        sections: 0.10,
        strings: 0.15,
        yara: 0.20,
        iocs: 0.15,
        resources: 0.05,
        entropy: 0.05,
        packer: 0.05,
      };

      let totalScore = 0;
      let totalWeight = 0;

      for (const [key, value] of Object.entries(features)) {
        if (value.score !== undefined) {
          totalScore += value.score * weights[key];
          totalWeight += weights[key];
        }
      }

      const overallScore = totalWeight > 0 ? totalScore / totalWeight : 0;

      // Determine if related
      const isRelated = overallScore >= 0.5;
      const relationshipType = this._determineRelationshipType(features, overallScore);

      // Generate explanation
      const explanation = this._generateSimilarityExplanation(features, overallScore, relationshipType);

      // Create similarity result
      const similarityResult = new SimilarityResult({
        sourceSample: sampleIdA,
        relatedSample: sampleIdB,
        similarityScore: overallScore,
        features: features,
        explanation: explanation,
        confidence: Math.min(overallScore + 0.1, 1.0),
        analysis: analysisId,
        isRelated: isRelated,
        relationshipType: relationshipType,
        calculatedAt: new Date(),
      });

      await similarityResult.save();

      logger.info(`Similarity calculated: ${sampleIdA} vs ${sampleIdB} = ${overallScore}`);
      return similarityResult;
    } catch (error) {
      logger.error(`Failed to calculate similarity: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Compare imports between two samples
   */
  static _compareImports(staticA, staticB) {
    if (!staticA || !staticB) {
      return { score: 0, matched: [], total: 0 };
    }

    const importsA = staticA.imports || [];
    const importsB = staticB.imports || [];

    const funcsA = new Set();
    for (const imp of importsA) {
      for (const func of imp.functions || []) {
        funcsA.add(func);
      }
    }

    const funcsB = new Set();
    for (const imp of importsB) {
      for (const func of imp.functions || []) {
        funcsB.add(func);
      }
    }

    const intersection = [...funcsA].filter(f => funcsB.has(f));
    const union = new Set([...funcsA, ...funcsB]);

    const score = union.size > 0 ? intersection.length / union.size : 0;

    return {
      score,
      matched: intersection.slice(0, 20),
      total: union.size,
    };
  }

  /**
   * Compare sections between two samples
   */
  static _compareSections(staticA, staticB) {
    if (!staticA || !staticB) {
      return { score: 0, matched: [], total: 0 };
    }

    const sectionsA = staticA.sections || [];
    const sectionsB = staticB.sections || [];

    const namesA = new Set(sectionsA.map(s => s.name));
    const namesB = new Set(sectionsB.map(s => s.name));

    const intersection = [...namesA].filter(n => namesB.has(n));
    const union = new Set([...namesA, ...namesB]);

    const score = union.size > 0 ? intersection.length / union.size : 0;

    return {
      score,
      matched: intersection,
      total: union.size,
    };
  }

  /**
   * Compare strings between two samples
   */
  static _compareStrings(staticA, staticB) {
    if (!staticA || !staticB) {
      return { score: 0, matched: [], total: 0 };
    }

    const stringsA = staticA.strings?.ascii || [];
    const stringsB = staticB.strings?.ascii || [];

    const setA = new Set(stringsA.slice(0, 500));
    const setB = new Set(stringsB.slice(0, 500));

    const intersection = [...setA].filter(s => setB.has(s));
    const union = new Set([...setA, ...setB]);

    const score = union.size > 0 ? intersection.length / union.size : 0;

    return {
      score,
      matched: intersection.slice(0, 20),
      total: union.size,
    };
  }

  /**
   * Compare YARA matches between two samples
   */
  static _compareYara(staticA, staticB) {
    if (!staticA || !staticB) {
      return { score: 0, matched: [], total: 0 };
    }

    const yaraA = staticA.yaraMatches || [];
    const yaraB = staticB.yaraMatches || [];

    const rulesA = new Set(yaraA.map(y => y.ruleName));
    const rulesB = new Set(yaraB.map(y => y.ruleName));

    const intersection = [...rulesA].filter(r => rulesB.has(r));
    const union = new Set([...rulesA, ...rulesB]);

    const score = union.size > 0 ? intersection.length / union.size : 0;

    return {
      score,
      matched: intersection,
      total: union.size,
    };
  }

  /**
   * Compare IOCs between two samples
   */
  static _compareIOCs(iocsA, iocsB) {
    if (!iocsA || !iocsB) {
      return { score: 0, matched: [], total: 0 };
    }

    const valuesA = new Set(iocsA.map(i => i.normalizedValue));
    const valuesB = new Set(iocsB.map(i => i.normalizedValue));

    const intersection = [...valuesA].filter(v => valuesB.has(v));
    const union = new Set([...valuesA, ...valuesB]);

    const score = union.size > 0 ? intersection.length / union.size : 0;

    return {
      score,
      matched: intersection.slice(0, 20),
      total: union.size,
    };
  }

  /**
   * Compare resources between two samples
   */
  static _compareResources(staticA, staticB) {
    if (!staticA || !staticB) {
      return { score: 0, matched: [], total: 0 };
    }

    const resourcesA = staticA.resources || [];
    const resourcesB = staticB.resources || [];

    const typesA = new Set(resourcesA.map(r => r.type));
    const typesB = new Set(resourcesB.map(r => r.type));

    const intersection = [...typesA].filter(t => typesB.has(t));
    const union = new Set([...typesA, ...typesB]);

    const score = union.size > 0 ? intersection.length / union.size : 0;

    return {
      score,
      matched: intersection,
      total: union.size,
    };
  }

  /**
   * Compare entropy between two samples
   */
  static _compareEntropy(staticA, staticB) {
    if (!staticA || !staticB) {
      return { score: 0, similarity: 0 };
    }

    const entropyA = staticA.entropy?.overall || 0;
    const entropyB = staticB.entropy?.overall || 0;

    // Calculate similarity based on entropy difference
    const diff = Math.abs(entropyA - entropyB);
    const similarity = Math.max(0, 1 - diff / 8);

    return {
      score: similarity,
      similarity: similarity,
    };
  }

  /**
   * Compare packer indicators between two samples
   */
  static _comparePacker(staticA, staticB) {
    if (!staticA || !staticB) {
      return { score: 0, matched: [], total: 0 };
    }

    // Check for packer indicators in entropy and sections
    const indicatorsA = this._getPackerIndicators(staticA);
    const indicatorsB = this._getPackerIndicators(staticB);

    const setA = new Set(indicatorsA);
    const setB = new Set(indicatorsB);

    const intersection = [...setA].filter(i => setB.has(i));
    const union = new Set([...setA, ...setB]);

    const score = union.size > 0 ? intersection.length / union.size : 0;

    return {
      score,
      matched: intersection,
      total: union.size,
    };
  }

  /**
   * Get packer indicators from static analysis
   */
  static _getPackerIndicators(staticData) {
    const indicators = [];

    // Check for high entropy sections
    const entropy = staticData.entropy || {};
    const highEntropy = entropy.highEntropySections || [];
    if (highEntropy.length > 0) {
      indicators.push('high_entropy');
    }

    // Check for suspicious section names
    const sections = staticData.sections || [];
    const suspiciousNames = ['upx', 'aspack', 'themida', 'vmprotect', 'enigma'];
    for (const section of sections) {
      if (suspiciousNames.some(n => section.name.toLowerCase().includes(n))) {
        indicators.push('packer_section');
        break;
      }
    }

    // Check for low import count (potential packed)
    const imports = staticData.imports || [];
    let funcCount = 0;
    for (const imp of imports) {
      funcCount += (imp.functions || []).length;
    }
    if (funcCount < 20) {
      indicators.push('low_import_count');
    }

    return indicators;
  }

  /**
   * Determine relationship type
   */
  static _determineRelationshipType(features, overallScore) {
    if (overallScore < 0.5) return 'unknown';

    if (features.yara.score > 0.7) return 'same_family';
    if (features.iocs.score > 0.6) return 'shared_iocs';
    if (features.imports.score > 0.7) return 'shared_imports';
    if (features.packer.score > 0.6) return 'same_packer';

    return 'similar_behavior';
  }

  /**
   * Generate similarity explanation
   */
  static _generateSimilarityExplanation(features, overallScore, relationshipType) {
    const parts = [];

    if (features.imports.score > 0.5) {
      parts.push(`${Math.round(features.imports.score * 100)}% import similarity`);
    }
    if (features.yara.score > 0.5) {
      parts.push(`${Math.round(features.yara.score * 100)}% YARA overlap`);
    }
    if (features.iocs.score > 0.4) {
      parts.push(`${Math.round(features.iocs.score * 100)}% IOC overlap`);
    }
    if (features.sections.score > 0.4) {
      parts.push(`${Math.round(features.sections.score * 100)}% section similarity`);
    }
    if (features.strings.score > 0.3) {
      parts.push(`${Math.round(features.strings.score * 100)}% string overlap`);
    }

    const scorePercent = Math.round(overallScore * 100);
    const relationshipLabels = {
      same_family: 'same malware family',
      shared_iocs: 'shared IOCs',
      shared_imports: 'shared imports',
      same_packer: 'same packer',
      similar_behavior: 'similar static behavior',
      unknown: 'unknown relationship',
    };

    return `Samples are ${scorePercent}% similar based on ${parts.join(', ')}. Relationship: ${relationshipLabels[relationshipType] || 'unknown'}.`;
  }

  /**
   * Get similarity results for a sample
   */
  static async getForSample(sampleId, page = 1, limit = 20) {
    try {
      const skip = (page - 1) * limit;

      const [results, total] = await Promise.all([
        SimilarityResult.find({
          $or: [
            { sourceSample: sampleId },
            { relatedSample: sampleId },
          ],
        })
          .sort({ similarityScore: -1 })
          .skip(skip)
          .limit(limit)
          .populate('sourceSample', 'filename sha256 fileSize')
          .populate('relatedSample', 'filename sha256 fileSize')
          .lean(),
        SimilarityResult.countDocuments({
          $or: [
            { sourceSample: sampleId },
            { relatedSample: sampleId },
          ],
        }),
      ]);

      return {
        results,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      logger.error(`Failed to get similarity results: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get related samples for a sample
   */
  static async getRelatedSamples(sampleId, minScore = 0.5) {
    try {
      const results = await SimilarityResult.find({
        $or: [
          { sourceSample: sampleId },
          { relatedSample: sampleId },
        ],
        similarityScore: { $gte: minScore },
        isRelated: true,
      })
        .sort({ similarityScore: -1 })
        .populate('sourceSample', 'filename sha256 fileSize')
        .populate('relatedSample', 'filename sha256 fileSize')
        .lean();

      // Extract the related samples (the one that's not the source)
      const related = results.map(result => {
        const isSource = result.sourceSample._id.toString() === sampleId;
        return {
          sample: isSource ? result.relatedSample : result.sourceSample,
          score: result.similarityScore,
          relationshipType: result.relationshipType,
          explanation: result.explanation,
          matchedFeatures: this._getMatchedFeatures(result),
        };
      });

      return related;
    } catch (error) {
      logger.error(`Failed to get related samples: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get matched features for display
   */
  static _getMatchedFeatures(result) {
    const features = [];

    if (result.features?.imports?.matched?.length > 0) {
      features.push({
        type: 'imports',
        items: result.features.imports.matched.slice(0, 10),
        score: result.features.imports.score,
      });
    }

    if (result.features?.yara?.matched?.length > 0) {
      features.push({
        type: 'yara',
        items: result.features.yara.matched,
        score: result.features.yara.score,
      });
    }

    if (result.features?.iocs?.matched?.length > 0) {
      features.push({
        type: 'iocs',
        items: result.features.iocs.matched.slice(0, 10),
        score: result.features.iocs.score,
      });
    }

    return features;
  }
}

module.exports = SimilarityService;