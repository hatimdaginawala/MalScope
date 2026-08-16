const mongoose = require('mongoose');

const threatAssessmentSchema = new mongoose.Schema(
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
    // Overall score and level
    score: {
      type: Number,
      min: 0,
      max: 100,
      required: [true, 'Risk score is required'],
    },
    level: {
      type: String,
      required: [true, 'Risk level is required'],
      enum: ['low', 'medium', 'high', 'critical'],
      index: true,
    },
    // Contributing factors
    contributors: {
      static: {
        score: Number,
        level: String,
        factors: [String],
        confidence: Number,
      },
      dynamic: {
        score: Number,
        level: String,
        factors: [String],
        confidence: Number,
      },
      virustotal: {
        score: Number,
        level: String,
        factors: [String],
        confidence: Number,
      },
      ioc: {
        score: Number,
        level: String,
        factors: [String],
        confidence: Number,
      },
      behavioral: {
        score: Number,
        level: String,
        factors: [String],
        confidence: Number,
      },
    },
    // Final assessment details
    finalVerdict: {
      type: String,
      enum: ['malicious', 'suspicious', 'benign', 'inconclusive', 'not_analyzed'],
      required: [true, 'Final verdict is required'],
    },
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.5,
    },
    // Explanation for the assessment
    explanation: {
      summary: String,
      detailed: [{
        heading: String,
        content: String,
        evidence: [String],
      }],
    },
    // Key findings that drove the assessment
    keyFindings: [{
      type: String,
      severity: String,
      description: String,
      evidence: String,
    }],
    // Reversibility/modifiability
    isEditable: {
      type: Boolean,
      default: true,
    },
    reviewed: {
      type: Boolean,
      default: false,
    },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
    },
    reviewedAt: Date,
    analystNotes: {
      type: String,
      trim: true,
    },
    // Versioning
    version: {
      type: String,
      default: '1.0.0',
    },
    generatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
// threatAssessmentSchema.index({ sample: 1, createdAt: -1 });
// threatAssessmentSchema.index({ analysis: 1 });
// threatAssessmentSchema.index({ level: 1 });
// threatAssessmentSchema.index({ finalVerdict: 1 });

// Static methods
threatAssessmentSchema.statics.getLatestForSample = function (sampleId) {
  return this.findOne({ sample: sampleId }).sort({ createdAt: -1 });
};

threatAssessmentSchema.statics.getByLevel = function (level) {
  return this.find({ level }).sort({ score: -1, createdAt: -1 }).populate('sample');
};

// Instance method to update assessment
threatAssessmentSchema.methods.updateAssessment = function (newData) {
  Object.assign(this, newData);
  this.generatedAt = new Date();
  return this.save();
};

// Virtual for overall summary
threatAssessmentSchema.virtual('summary').get(function () {
  return {
    level: this.level,
    score: this.score,
    verdict: this.finalVerdict,
    confidence: this.confidence,
    generatedAt: this.generatedAt,
  };
});

module.exports = mongoose.model('ThreatAssessment', threatAssessmentSchema);