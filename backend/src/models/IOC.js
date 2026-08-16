const mongoose = require('mongoose');

const iocSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      required: [true, 'IOC type is required'],
      enum: ['sha256', 'md5', 'sha1', 'ip', 'domain', 'url', 'file_path', 'registry_key', 'email', 'process_name', 'service', 'other'],
      index: true,
    },
    value: {
      type: String,
      required: [true, 'IOC value is required'],
      trim: true,
      index: true,
    },
    normalizedValue: {
      type: String,
      required: true,
      index: true,
    },
    // Source information
    source: {
      type: String,
      required: [true, 'Source is required'],
      enum: ['static_analysis', 'dynamic_analysis', 'virustotal', 'manual', 'yara', 'correlation'],
    },
    sample: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'MalwareSample',
      required: [true, 'Sample reference is required'],
      index: true,
    },
    analysis: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Analysis',
      index: true,
    },
    // Confidence and severity
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.5,
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium',
    },
    // Additional metadata
    context: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
    },
    tags: [{
      type: String,
      trim: true,
    }],
    firstSeen: {
      type: Date,
      default: Date.now,
    },
    lastSeen: {
      type: Date,
      default: Date.now,
    },
    references: [{
      type: String,
      trim: true,
    }],
    // Malware family associations
    malwareFamily: {
      type: String,
      trim: true,
    },
    // Threat intelligence enrichment
    threatIntel: {
      isMalicious: Boolean,
      detectionRatio: String,
      threatTags: [String],
    },
    // Active/retired status
    isActive: {
      type: Boolean,
      default: true,
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

// Compound indexes
iocSchema.index({ type: 1, normalizedValue: 1 });
iocSchema.index({ sample: 1, type: 1 });
iocSchema.index({ confidence: -1, severity: 1 });
iocSchema.index({ value: 'text' }, { weights: { value: 10 } });

// Static methods
iocSchema.statics.findByValue = function (type, value) {
  const normalized = value.toLowerCase().trim();
  return this.findOne({ type, normalizedValue: normalized });
};

iocSchema.statics.getForSample = function (sampleId) {
  return this.find({ sample: sampleId }).sort({ confidence: -1, severity: 1 });
};

// Instance method to update lastSeen
iocSchema.methods.updateSeen = function () {
  this.lastSeen = new Date();
  return this.save();
};

module.exports = mongoose.model('IOC', iocSchema);