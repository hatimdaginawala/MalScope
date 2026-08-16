const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  sample: { type: mongoose.Schema.Types.ObjectId, ref: 'MalwareSample', required: true },
  analysis: { type: mongoose.Schema.Types.ObjectId, ref: 'Analysis', required: true },
  fileInfo: mongoose.Schema.Types.Mixed,
  sections: [mongoose.Schema.Types.Mixed],
  imports: [mongoose.Schema.Types.Mixed],
  exports: [mongoose.Schema.Types.Mixed],
  strings: mongoose.Schema.Types.Mixed,
  entropy: mongoose.Schema.Types.Mixed,
  resources: [mongoose.Schema.Types.Mixed],
  yaraMatches: [mongoose.Schema.Types.Mixed],
  findings: [mongoose.Schema.Types.Mixed],
  processedAt: { type: Date, default: Date.now },
  processingDuration: Number,
  warnings: [String],
  errors: [String],
  version: { type: String, default: '1.0.0' },
  rawResult: mongoose.Schema.Types.Mixed,
}, { timestamps: true });

// Export as 'StaticAnalysis' so the Analysis model can find it
module.exports = mongoose.model('StaticAnalysis', schema);