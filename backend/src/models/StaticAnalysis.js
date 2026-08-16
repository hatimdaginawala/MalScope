const mongoose = require('mongoose');

const staticAnalysisSchema = new mongoose.Schema(
  {
    sample: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'MalwareSample',
      required: [true, 'Sample reference is required'],
      index: true,
    },
    analysis: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Analysis',
      required: [true, 'Analysis reference is required'],
      index: true,
    },
    // File information
    fileInfo: {
      filename: String,
      fileSize: Number,
      fileType: String,
      mimeType: String,
      peType: String,
      arch: String,
      compileTime: Date,
      linkerVersion: String,
      entryPoint: Number,
      imageBase: Number,
      subsystem: String,
    },
    // PE sections
    sections: [{
      name: String,
      virtualAddress: Number,
      virtualSize: Number,
      rawSize: Number,
      characteristics: String,
      entropy: Number,
    }],
    // Imports
    imports: [{
      dll: String,
      functions: [String],
    }],
    // Exports
    exports: [{
      name: String,
      ordinal: Number,
      address: Number,
    }],
    // Strings
    strings: {
      ascii: [String],
      unicode: [String],
      suspicious: [String],
    },
    // Entropy analysis
    entropy: {
      overall: Number,
      sections: [
        {
          name: String,
          entropy: Number,
        },
      ],
      highEntropySections: [String],
    },
    // Resources
    resources: [{
      type: String,
      id: Number,
      language: Number,
      size: Number,
      sha256: String,
    }],
    // YARA matches
    yaraMatches: [{
      ruleName: String,
      namespace: String,
      tags: [String],
      meta: Map,
      strings: [{
        id: String,
        string: String,
        offset: Number,
        length: Number,
      }],
    }],
    // Findings
    findings: [{
      type: String,
      severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
      },
      description: String,
      evidence: String,
      confidence: {
        type: Number,
        min: 0,
        max: 1,
      },
    }],
    // Process metadata
    processedAt: {
      type: Date,
      default: Date.now,
    },
    processingDuration: Number,
    warnings: [String],
    errors: [String],
    version: {
      type: String,
      default: '1.0.0',
    },
    // Raw analysis result (for debugging/reference)
    rawResult: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
// staticAnalysisSchema.index({ sample: 1, createdAt: -1 });
// staticAnalysisSchema.index({ analysis: 1 });

// Static method to get latest analysis for a sample
staticAnalysisSchema.statics.getLatestForSample = function (sampleId) {
  return this.findOne({ sample: sampleId }).sort({ createdAt: -1 });
};

module.exports = mongoose.model('StaticAnalysis', staticAnalysisSchema);