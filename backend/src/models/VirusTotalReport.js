const mongoose = require('mongoose');

const virusTotalReportSchema = new mongoose.Schema(
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
    // Request metadata
    request: {
      hash: String,
      url: String,
      timestamp: Date,
      responseCode: Number,
    },
    // Detection statistics
    stats: {
      malicious: {
        type: Number,
        default: 0,
      },
      suspicious: {
        type: Number,
        default: 0,
      },
      undetected: {
        type: Number,
        default: 0,
      },
      harmless: {
        type: Number,
        default: 0,
      },
      timeout: {
        type: Number,
        default: 0,
      },
      total: {
        type: Number,
        default: 0,
      },
    },
    // Detection results by engine
    detections: [{
      engine: String,
      detection: String,
      version: String,
      update: Date,
      result: String,
      method: String,
      engineVersion: String,
      engineUpdate: Date,
    }],
    // Threat intelligence
    threatIntelligence: {
      threatNames: [String],
      families: [String],
      tags: [String],
      categories: {
        type: Map,
        of: [String],
      },
    },
    // File information from VT
    fileInfo: {
      sha256: String,
      md5: String,
      sha1: String,
      fileSize: Number,
      fileType: String,
      magic: String,
      names: [String],
      signatures: [String],
      popularity: {
        rank: Number,
        votes: Number,
      },
    },
    // Reputation
    reputation: {
      score: Number,
      positives: Number,
      total: Number,
    },
    // Relationship data
    related: {
      samples: [{
        hash: String,
        sha256: String,
        detectionRatio: String,
        date: Date,
      }],
      domains: [{
        domain: String,
        resolution: String,
        lastResolved: Date,
      }],
      ips: [{
        ip: String,
        country: String,
        asOwner: String,
        lastSeen: Date,
      }],
    },
    // Raw response (for debugging)
    rawResponse: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
    },
    // Metadata
    fetchedAt: {
      type: Date,
      default: Date.now,
    },
    version: {
      type: String,
      default: '3.0', // VT API version
    },
    // Cache control
    cacheTtl: Number,
    isCached: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
virusTotalReportSchema.index({ sample: 1, createdAt: -1 });
virusTotalReportSchema.index({ analysis: 1 });
virusTotalReportSchema.index({ 'stats.malicious': 1 });
virusTotalReportSchema.index({ 'threatIntelligence.families': 1 });

// Static method to get latest report
virusTotalReportSchema.statics.getLatestForSample = function (sampleId) {
  return this.findOne({ sample: sampleId }).sort({ createdAt: -1 });
};

// Instance method to check if report indicates malicious
virusTotalReportSchema.methods.isMalicious = function () {
  return this.stats && this.stats.malicious > 0;
};

module.exports = mongoose.model('VirusTotalReport', virusTotalReportSchema);