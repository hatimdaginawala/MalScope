const mongoose = require('mongoose');

const staticAnalysisSchema = new mongoose.Schema(
  {
    sample: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'MalwareSample',
      required: [true, 'Sample reference is required'],
    },
    analysis: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Analysis',
      required: [true, 'Analysis reference is required'],
    },
    
    // ===== File Information =====
    fileInfo: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    
    // ===== Header Analysis =====
    dosHeader: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    coffHeader: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    optionalHeader: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    dataDirectories: {
      type: [mongoose.Schema.Types.Mixed],
      default: [],
    },
    
    // ===== Sections =====
    sections: {
      type: [mongoose.Schema.Types.Mixed],
      default: [],
    },
    
    // ===== Imports/Exports =====
    imports: {
      type: [mongoose.Schema.Types.Mixed],
      default: [],
    },
    exports: {
      type: [mongoose.Schema.Types.Mixed],
      default: [],
    },
    
    // ===== Strings =====
    strings: {
      type: mongoose.Schema.Types.Mixed,
      default: { ascii: [], unicode: [], suspicious: [] },
    },
    
    // ===== Entropy =====
    entropy: {
      type: mongoose.Schema.Types.Mixed,
      default: { overall: 0, sections: [], highEntropySections: [] },
    },
    
    // ===== Resources =====
    resources: {
      type: [mongoose.Schema.Types.Mixed],
      default: [],
    },
    
    // ===== TLS =====
    tls: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    
    // ===== Debug Information =====
    debugInfo: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    
    // ===== Rich Header =====
    richHeader: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    
    // ===== Digital Signature =====
    signature: {
      type: mongoose.Schema.Types.Mixed,
      default: { signed: false },
    },
    
    // ===== API Intelligence =====
    apiIntelligence: {
      type: mongoose.Schema.Types.Mixed,
      default: {
        total_apis: 0,
        total_categories: 0,
        categories: {},
        severity_summary: { low: 0, medium: 0, high: 0, critical: 0 },
        top_categories: [],
        capabilities: [],
      },
    },
    highRiskApis: {
      type: [mongoose.Schema.Types.Mixed],
      default: [],
    },
    
    // ===== YARA =====
    yaraMatches: {
      type: [mongoose.Schema.Types.Mixed],
      default: [],
    },
    
    // ===== Findings =====
    findings: {
      type: [mongoose.Schema.Types.Mixed],
      default: [],
    },
    
    processedAt: {
      type: Date,
      default: Date.now,
    },
    processingDuration: Number,
    warnings: {
      type: [String],
      default: [],
    },
    errors: {
      type: [String],
      default: [],
    },
    version: {
      type: String,
      default: '2.0.0',
    },
    rawResult: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

staticAnalysisSchema.index({ sample: 1, createdAt: -1 });
staticAnalysisSchema.index({ analysis: 1 });

staticAnalysisSchema.statics.getLatestForSample = function (sampleId) {
  return this.findOne({ sample: sampleId }).sort({ createdAt: -1 });
};

module.exports = mongoose.model('StaticAnalysis', staticAnalysisSchema);