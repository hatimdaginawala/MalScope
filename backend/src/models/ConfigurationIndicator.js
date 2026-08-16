const mongoose = require('mongoose');

/**
 * ConfigurationIndicator Model
 * Stores configuration indicators extracted from samples
 * These are potential C2 servers, mutex names, campaign IDs, etc.
 */
const configurationIndicatorSchema = new mongoose.Schema(
  {
    // Type of configuration indicator
    type: {
      type: String,
      required: [true, 'Indicator type is required'],
      enum: [
        'c2_domain',
        'c2_ip',
        'c2_url',
        'mutex',
        'campaign_id',
        'bot_id',
        'registry_path',
        'file_path',
        'user_agent',
        'encryption_key',
        'salt',
        'campaign_name',
        'version',
        'build_id',
        'other'
      ],
      index: true,
    },
    
    // The actual value
    value: {
      type: String,
      required: [true, 'Indicator value is required'],
      trim: true,
      index: true,
    },
    
    // Normalized value for case-insensitive search
    normalizedValue: {
      type: String,
      required: true,
      index: true,
    },
    
    // Where this was found (string, resource, import, etc.)
    sourceType: {
      type: String,
      required: [true, 'Source type is required'],
      enum: ['string', 'resource', 'import', 'section', 'header', 'yara', 'other'],
    },
    
    // Confidence in this indicator (0.0 to 1.0)
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.5,
    },
    
    // Severity of this indicator
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium',
    },
    
    // Reference to the sample
    sample: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'MalwareSample',
      required: [true, 'Sample reference is required'],
      index: true,
    },
    
    // Reference to the analysis
    analysis: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Analysis',
      index: true,
    },
    
    // Evidence supporting this indicator (e.g., the actual string found)
    evidence: {
      type: String,
      trim: true,
    },
    
    // Additional context
    context: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
    },
    
    // Whether this indicator is active/verified
    isActive: {
      type: Boolean,
      default: true,
    },
    
    // Tags for categorization
    tags: [{
      type: String,
      trim: true,
    }],
    
    // When this was first and last seen
    firstSeen: {
      type: Date,
      default: Date.now,
    },
    lastSeen: {
      type: Date,
      default: Date.now,
    },
    
    // User notes
    notes: {
      type: String,
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

// Compound indexes for efficient queries
configurationIndicatorSchema.index({ type: 1, normalizedValue: 1 });
configurationIndicatorSchema.index({ sample: 1, type: 1 });
configurationIndicatorSchema.index({ confidence: -1, severity: 1 });

// Static methods
configurationIndicatorSchema.statics.findByValue = function (type, value) {
  const normalized = value.toLowerCase().trim();
  return this.findOne({ type, normalizedValue: normalized });
};

configurationIndicatorSchema.statics.getForSample = function (sampleId) {
  return this.find({ sample: sampleId })
    .sort({ confidence: -1, severity: -1 })
    .lean();
};

configurationIndicatorSchema.statics.getHighConfidence = function (sampleId, minConfidence = 0.7) {
  return this.find({
    sample: sampleId,
    confidence: { $gte: minConfidence },
  })
    .sort({ confidence: -1 })
    .lean();
};

// Instance methods
configurationIndicatorSchema.methods.updateSeen = function () {
  this.lastSeen = new Date();
  return this.save();
};

// Virtual for display summary
configurationIndicatorSchema.virtual('summary').get(function () {
  return {
    type: this.type,
    value: this.value,
    confidence: this.confidence,
    severity: this.severity,
    source: this.sourceType,
  };
});

module.exports = mongoose.model('ConfigurationIndicator', configurationIndicatorSchema);