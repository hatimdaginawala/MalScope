const mongoose = require('mongoose');

// Analysis status enum
const ANALYSIS_STATUS = {
  QUEUED: 'queued',
  PREPARING: 'preparing',
  STATIC_ANALYSIS: 'static_analysis',
  VT_ENRICHMENT: 'vt_enrichment',
  DYNAMIC_ANALYSIS: 'dynamic_analysis',
  COLLECTING: 'collecting',
  CORRELATING: 'correlating',
  COMPLETED: 'completed',
  FAILED: 'failed',
  CLEANUP: 'cleanup',
};

const analysisSchema = new mongoose.Schema(
  {
    sample: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'MalwareSample',
      required: [true, 'Sample reference is required'],
      index: true,
    },
    status: {
      type: String,
      enum: Object.values(ANALYSIS_STATUS),
      default: ANALYSIS_STATUS.QUEUED,
      index: true,
    },
    stage: {
      type: String,
      enum: Object.values(ANALYSIS_STATUS),
      default: ANALYSIS_STATUS.QUEUED,
    },
    startedAt: {
      type: Date,
    },
    completedAt: {
      type: Date,
    },
    error: {
      message: String,
      stage: String,
      timestamp: Date,
      stack: String,
    },
    // References to analysis components
    staticAnalysis: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'StaticAnalysis',
    },
    dynamicAnalysis: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'DynamicAnalysis',
    },
    virusTotalReport: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'VirusTotalReport',
    },
    threatAssessment: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'ThreatAssessment',
    },
    // Analysis environment
    environment: {
      nodeVersion: String,
      pythonVersion: String,
      vmName: String,
      vmSnapshot: String,
    },
    // Analysis metadata
    analysisVersion: {
      type: String,
      default: '1.0.0',
    },
    duration: {
      type: Number, // milliseconds
    },
    logs: [{
      timestamp: Date,
      level: {
        type: String,
        enum: ['info', 'warn', 'error', 'debug'],
      },
      message: String,
    }],
    completed: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
analysisSchema.index({ sample: 1, status: 1 });
analysisSchema.index({ status: 1, createdAt: -1 });
analysisSchema.index({ completed: 1, createdAt: -1 });

// Static methods
analysisSchema.statics.getStatusEnum = function () {
  return ANALYSIS_STATUS;
};

// Instance methods
analysisSchema.methods.updateStatus = function (newStatus, logMessage = null) {
  const validTransitions = {
    queued: ['preparing', 'failed'],
    preparing: ['static_analysis', 'failed'],
    static_analysis: ['vt_enrichment', 'dynamic_analysis', 'failed'],
    vt_enrichment: ['dynamic_analysis', 'completed', 'failed'],
    dynamic_analysis: ['collecting', 'failed'],
    collecting: ['correlating', 'failed'],
    correlating: ['completed', 'failed'],
    completed: [],
    failed: ['cleanup'],
    cleanup: [],
  };

  // Allow cleanup from any state
  if (newStatus === 'cleanup') {
    this.status = newStatus;
    this.stage = newStatus;
    if (logMessage) {
      this.logs.push({
        timestamp: new Date(),
        level: 'info',
        message: logMessage,
      });
    }
    return this.save();
  }

  // Validate transition
  const allowed = validTransitions[this.status] || [];
  if (!allowed.includes(newStatus) && this.status !== newStatus) {
    throw new Error(
      `Invalid status transition: ${this.status} -> ${newStatus}. Allowed: ${allowed.join(', ')}`
    );
  }

  this.status = newStatus;
  this.stage = newStatus;

  if (newStatus === 'completed') {
    this.completedAt = new Date();
    this.completed = true;
    if (this.startedAt) {
      this.duration = this.completedAt - this.startedAt;
    }
  }

  if (newStatus === 'failed') {
    this.completed = false;
  }

  if (newStatus === 'queued' && !this.startedAt) {
    this.startedAt = new Date();
  }

  if (logMessage) {
    this.logs.push({
      timestamp: new Date(),
      level: 'info',
      message: logMessage,
    });
  }

  return this.save();
};

analysisSchema.methods.setError = function (errorMessage, errorStage, errorStack = null) {
  this.status = 'failed';
  this.stage = errorStage || this.stage;
  this.error = {
    message: errorMessage,
    stage: errorStage || this.stage,
    timestamp: new Date(),
    stack: errorStack,
  };
  this.completed = false;
  this.logs.push({
    timestamp: new Date(),
    level: 'error',
    message: `Failed at ${this.stage}: ${errorMessage}`,
  });
  return this.save();
};

analysisSchema.methods.addLog = function (message, level = 'info') {
  this.logs.push({
    timestamp: new Date(),
    level,
    message,
  });
  return this.save();
};

module.exports = {
  Analysis: mongoose.model('Analysis', analysisSchema),
  ANALYSIS_STATUS,
};