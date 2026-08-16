const mongoose = require('mongoose');

/**
 * SimilarityResult Model
 * Stores similarity analysis results between pairs of samples
 */
const similarityResultSchema = new mongoose.Schema(
  {
    // Source sample (the one being analyzed)
    sourceSample: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'MalwareSample',
      required: [true, 'Source sample reference is required'],
      index: true,
    },
    
    // Related sample (the one being compared)
    relatedSample: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'MalwareSample',
      required: [true, 'Related sample reference is required'],
      index: true,
    },
    
    // Overall similarity score (0.0 to 1.0)
    similarityScore: {
      type: Number,
      required: [true, 'Similarity score is required'],
      min: 0,
      max: 1,
    },
    
    // Individual feature similarities
    features: {
      imports: {
        score: { type: Number, min: 0, max: 1, default: 0 },
        matched: [String],
        total: { type: Number, default: 0 },
      },
      sections: {
        score: { type: Number, min: 0, max: 1, default: 0 },
        matched: [String],
        total: { type: Number, default: 0 },
      },
      strings: {
        score: { type: Number, min: 0, max: 1, default: 0 },
        matched: [String],
        total: { type: Number, default: 0 },
      },
      yara: {
        score: { type: Number, min: 0, max: 1, default: 0 },
        matched: [String],
        total: { type: Number, default: 0 },
      },
      iocs: {
        score: { type: Number, min: 0, max: 1, default: 0 },
        matched: [String],
        total: { type: Number, default: 0 },
      },
      resources: {
        score: { type: Number, min: 0, max: 1, default: 0 },
        matched: [String],
        total: { type: Number, default: 0 },
      },
      entropy: {
        score: { type: Number, min: 0, max: 1, default: 0 },
        similarity: { type: Number, min: 0, max: 1, default: 0 },
      },
      packer: {
        score: { type: Number, min: 0, max: 1, default: 0 },
        matched: [String],
        total: { type: Number, default: 0 },
      },
    },
    
    // Combined similarity explanation
    explanation: {
      type: String,
      trim: true,
    },
    
    // Confidence in the similarity assessment
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.5,
    },
    
    // Analysis that generated this result
    analysis: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Analysis',
      index: true,
    },
    
    // Whether these samples are considered related
    isRelated: {
      type: Boolean,
      default: false,
    },
    
    // Relationship type if known
    relationshipType: {
      type: String,
      enum: [
        'same_family',
        'similar_behavior',
        'shared_iocs',
        'shared_imports',
        'shared_yara',
        'same_packer',
        'unknown',
      ],
      default: 'unknown',
    },
    
    // Additional metadata
    metadata: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
    },
    
    // When this similarity was calculated
    calculatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

// Compound indexes
similarityResultSchema.index({ sourceSample: 1, relatedSample: 1 }, { unique: true });
similarityResultSchema.index({ sourceSample: 1, similarityScore: -1 });
similarityResultSchema.index({ relatedSample: 1, similarityScore: -1 });
similarityResultSchema.index({ isRelated: 1, similarityScore: -1 });

// Static methods
similarityResultSchema.statics.getForSample = function (sampleId, limit = 20) {
  return this.find({
    $or: [
      { sourceSample: sampleId },
      { relatedSample: sampleId },
    ],
    isRelated: true,
  })
    .sort({ similarityScore: -1 })
    .limit(limit)
    .populate('sourceSample', 'filename sha256 fileSize')
    .populate('relatedSample', 'filename sha256 fileSize')
    .lean();
};

similarityResultSchema.statics.getRelatedSamples = function (sampleId, minScore = 0.5) {
  return this.find({
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
};

similarityResultSchema.statics.findBetween = function (sampleIdA, sampleIdB) {
  return this.findOne({
    $or: [
      { sourceSample: sampleIdA, relatedSample: sampleIdB },
      { sourceSample: sampleIdB, relatedSample: sampleIdA },
    ],
  }).lean();
};

// Instance methods
similarityResultSchema.methods.updateScore = function (newScore) {
  this.similarityScore = newScore;
  this.isRelated = newScore >= 0.5;
  return this.save();
};

// Virtual for determining if highly similar
similarityResultSchema.virtual('isHighlySimilar').get(function () {
  return this.similarityScore >= 0.7;
});

// Virtual for summary
similarityResultSchema.virtual('summary').get(function () {
  return {
    score: this.similarityScore,
    isRelated: this.isRelated,
    confidence: this.confidence,
    explanation: this.explanation,
    calculatedAt: this.calculatedAt,
  };
});

module.exports = mongoose.model('SimilarityResult', similarityResultSchema);