const mongoose = require('mongoose');

const behaviorSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      required: [true, 'Behavior type is required'],
      enum: [
        // Existing types
        'process_injection',
        'file_drop',
        'persistence',
        'registry_modification',
        'network_communication',
        'process_creation',
        'command_execution',
        'anti_debug',
        'anti_vm',
        'data_obfuscation',
        'privilege_escalation',
        'credential_access',
        'defense_evasion',
        'discovery',
        'collection',
        'exfiltration',
        'ransomware_behavior',
        'other',
        // New types for static analysis
        'network_communication_capability',
        'file_manipulation',
        'process_manipulation',
        'persistence_capability',
        'registry_manipulation',
        'anti_analysis',
        'crypto_encryption',
        'command_execution_capability',
        'data_theft',
        'suspicious_import',
        'suspicious_strings',
        'high_entropy',
        'yara_match',
      ],
      index: true,
    },
    description: {
      type: String,
      required: [true, 'Description is required'],
      trim: true,
    },
    severity: {
      type: String,
      required: [true, 'Severity is required'],
      enum: ['low', 'medium', 'high', 'critical'],
      index: true,
    },
    evidence: [{
      type: String,
      trim: true,
    }],
    source: {
      type: String,
      required: [true, 'Source is required'],
      enum: ['static_analysis', 'dynamic_analysis', 'virustotal', 'correlation', 'manual'],
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
      required: [true, 'Analysis reference is required'],
      index: true,
    },
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.5,
    },
    correlation: {
      relatedBehaviors: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Behavior',
      }],
      correlationScore: Number,
    },
    eventReferences: [{
      type: String,
      description: String,
    }],
    malwareFamily: {
      type: String,
      trim: true,
    },
    mitre: {
      tactic: String,
      technique: String,
      techniqueId: String,
      subtechnique: String,
    },
    tags: [{
      type: String,
      trim: true,
    }],
    notes: {
      type: String,
      trim: true,
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
  },
  {
    timestamps: true,
  }
);

// Indexes
behaviorSchema.index({ sample: 1, createdAt: -1 });
behaviorSchema.index({ analysis: 1 });
behaviorSchema.index({ type: 1, severity: 1 });
behaviorSchema.index({ 'mitre.techniqueId': 1 });

// Static methods
behaviorSchema.statics.getForSample = function (sampleId) {
  return this.find({ sample: sampleId })
    .sort({ severity: -1, confidence: -1 })
    .populate('correlation.relatedBehaviors');
};

behaviorSchema.statics.getByType = function (type) {
  return this.find({ type }).sort({ severity: -1, confidence: -1 });
};

// Instance method to add evidence
behaviorSchema.methods.addEvidence = function (evidenceString) {
  if (!this.evidence.includes(evidenceString)) {
    this.evidence.push(evidenceString);
  }
  return this.save();
};

module.exports = mongoose.model('Behavior', behaviorSchema);