const mongoose = require('mongoose');

const dynamicAnalysisSchema = new mongoose.Schema(
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
    // Execution environment
    environment: {
      vmName: String,
      snapshot: String,
      executionTimeout: Number,
      networkEnabled: Boolean,
      osVersion: String,
    },
    // Process activity
    processes: [{
      pid: Number,
      ppid: Number,
      name: String,
      path: String,
      commandLine: String,
      startTime: Date,
      endTime: Date,
      exitCode: Number,
      childPids: [Number],
      integrityLevel: String,
      user: String,
    }],
    // File activity
    fileEvents: [{
      path: String,
      operation: {
        type: String,
        enum: ['create', 'modify', 'delete', 'rename', 'read'],
      },
      processId: Number,
      processName: String,
      newPath: String, // For rename operations
      size: Number,
      sha256: String,
      timestamp: Date,
    }],
    // Registry activity
    registryEvents: [{
      key: String,
      value: String,
      data: String,
      operation: {
        type: String,
        enum: ['create', 'modify', 'delete', 'query'],
      },
      processId: Number,
      processName: String,
      timestamp: Date,
    }],
    // Persistence indicators
    persistence: [{
      type: {
        type: String,
        enum: ['registry_run', 'registry_runonce', 'service', 'scheduled_task', 'startup_folder', 'other'],
      },
      path: String,
      command: String,
      processId: Number,
      timestamp: Date,
      confidence: Number,
    }],
    // Network activity
    networkEvents: [{
      protocol: {
        type: String,
        enum: ['tcp', 'udp', 'dns'],
      },
      sourceIp: String,
      sourcePort: Number,
      destinationIp: String,
      destinationPort: Number,
      hostname: String, // For DNS
      processId: Number,
      processName: String,
      bytesSent: Number,
      bytesReceived: Number,
      timestamp: Date,
    }],
    // Behavioral findings
    behaviors: [{
      type: String,
      severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
      },
      description: String,
      evidence: [String],
      confidence: Number,
      timestamp: Date,
    }],
    // IOCs extracted from dynamic analysis
    iocs: [{
      type: {
        type: String,
        enum: ['ip', 'domain', 'url', 'file_path', 'registry_key', 'process_name', 'hash'],
      },
      value: String,
      source: String,
      confidence: Number,
    }],
    // Execution metadata
    execution: {
      startedAt: Date,
      endedAt: Date,
      duration: Number,
      exitCode: Number,
      timeout: Boolean,
    },
    // Telemetry processing
    telemetrySource: {
      type: String,
      default: 'sysmon',
    },
    processedAt: Date,
    processingDuration: Number,
    warnings: [String],
    errors: [String],
    version: {
      type: String,
      default: '1.0.0',
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
// dynamicAnalysisSchema.index({ sample: 1, createdAt: -1 });
// dynamicAnalysisSchema.index({ analysis: 1 });
// dynamicAnalysisSchema.index({ 'processes.pid': 1 });
// dynamicAnalysisSchema.index({ 'networkEvents.destinationIp': 1 });
// dynamicAnalysisSchema.index({ 'fileEvents.path': 1 });

// Static method to get latest analysis for a sample
dynamicAnalysisSchema.statics.getLatestForSample = function (sampleId) {
  return this.findOne({ sample: sampleId }).sort({ createdAt: -1 });
};

module.exports = mongoose.model('DynamicAnalysis', dynamicAnalysisSchema);