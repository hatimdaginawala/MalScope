const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Username is required'],
      unique: true,
      trim: true,
      minlength: [3, 'Username must be at least 3 characters'],
      maxlength: [30, 'Username cannot exceed 30 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      trim: true,
      lowercase: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address'],
    },
    passwordHash: {
      type: String,
      required: [true, 'Password hash is required'],
      select: false, // Don't return by default
    },
    role: {
      type: String,
      enum: ['analyst', 'admin', 'viewer'],
      default: 'analyst',
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    lastLogin: {
      type: Date,
    },
    preferences: {
      type: Map,
      of: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

// Indexes
userSchema.index({ username: 1 });
userSchema.index({ email: 1 });

// Virtual for full name or display name
userSchema.virtual('displayName').get(function () {
  return this.username;
});

// Method to check if user has permission
userSchema.methods.hasPermission = function (requiredRole) {
  const roleHierarchy = {
    viewer: 0,
    analyst: 1,
    admin: 2,
  };
  return roleHierarchy[this.role] >= roleHierarchy[requiredRole];
};

module.exports = mongoose.model('User', userSchema);