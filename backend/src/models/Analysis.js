const mongoose = require('mongoose');

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
    },
    status: {
      type: String,
      enum: Object.values(ANALYSIS_STATUS),
      default: ANALYSIS_STATUS.QUEUED,
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
    errorInfo: {
      message: String,
      stage: String,
      timestamp: Date,
      stack: String,
    },
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
    environment: {
      nodeVersion: String,
      pythonVersion: String,
      vmName: String,
      vmSnapshot: String,
    },
    analysisVersion: {
      type: String,
      default: '1.0.0',
    },
    duration: {
      type: Number,
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

analysisSchema.statics.getStatusEnum = function () {
  return ANALYSIS_STATUS;
};

analysisSchema.methods.updateStatus = function (newStatus, logMessage = null) {
  // Define valid transitions
  const validTransitions = {
    'queued': ['preparing', 'failed'],
    'preparing': ['static_analysis', 'failed'],
    'static_analysis': ['vt_enrichment', 'dynamic_analysis', 'failed'],
    'vt_enrichment': ['dynamic_analysis', 'completed', 'failed'],
    'dynamic_analysis': ['collecting', 'failed'],
    'collecting': ['correlating', 'failed'],
    'correlating': ['completed', 'failed'],
    'completed': [],
    'failed': ['cleanup'],
    'cleanup': [],
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
    return this;
  }

  // Validate transition
  const allowed = validTransitions[this.status] || [];
  if (!allowed.includes(newStatus) && this.status !== newStatus) {
    throw new Error(
      `Invalid status transition: ${this.status} -> ${newStatus}. Allowed: ${allowed.join(', ')}`
    );
  }

  // Update status
  this.status = newStatus;
  this.stage = newStatus;

  // Set timestamps
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

  // Set startedAt when first starting
  if (newStatus === 'queued' && !this.startedAt) {
    this.startedAt = new Date();
  }

  // Add log
  if (logMessage) {
    this.logs.push({
      timestamp: new Date(),
      level: 'info',
      message: logMessage,
    });
  }

  return this;
};

analysisSchema.methods.setError = function (errorMessage, errorStage, errorStack = null) {
  this.status = 'failed';
  this.stage = errorStage || this.stage || 'failed';
  this.errorInfo = {
    message: errorMessage,
    stage: this.stage,
    timestamp: new Date(),
    stack: errorStack,
  };
  this.completed = false;
  this.logs.push({
    timestamp: new Date(),
    level: 'error',
    message: `Failed at ${this.stage}: ${errorMessage}`,
  });
  return this;
};

analysisSchema.methods.addLog = function (message, level = 'info') {
  this.logs.push({
    timestamp: new Date(),
    level,
    message,
  });
  return this;
};

module.exports = {
  Analysis: mongoose.model('Analysis', analysisSchema),
  ANALYSIS_STATUS,
};