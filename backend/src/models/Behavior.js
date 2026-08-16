const mongoose = require('mongoose');

const behaviorSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      required: [true, 'Behavior type is required'],
      enum: [
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
    // Evidence supporting this behavior
    evidence: [{
      type: String,
      trim: true,
    }],
    // Source of the behavior
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
    // Confidence score
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.5,
    },
    // Correlation data
    correlation: {
      relatedBehaviors: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Behavior',
      }],
      correlationScore: Number,
    },
    // References to specific events
    eventReferences: [{
      type: String,
      description: String,
    }],
    // Malware family association
    malwareFamily: {
      type: String,
      trim: true,
    },
    // MITRE ATT&CK mapping
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
    // User notes
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
// behaviorSchema.index({ sample: 1, createdAt: -1 });
// behaviorSchema.index({ analysis: 1 });
// behaviorSchema.index({ type: 1, severity: 1 });
// behaviorSchema.index({ 'mitre.techniqueId': 1 });

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