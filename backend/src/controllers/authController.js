const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const logger = require('../utils/logger');
const environment = require('../config/environment');
const { ApiError } = require('../middleware/errorMiddleware');

class AuthController {
  /**
   * Generate JWT token (static method)
   */
  static _generateToken(user) {
    const payload = {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
    };

    return jwt.sign(payload, environment.jwtSecret, {
      expiresIn: '7d',
    });
  }

  /**
   * Register a new user
   * POST /api/v1/auth/register
   */
  static async register(req, res, next) {
    try {
      const { username, email, password, role } = req.body;

      // Check if user exists
      const existingUser = await User.findOne({
        $or: [{ username }, { email }],
      });

      if (existingUser) {
        throw new ApiError(409, 'User already exists with this username or email');
      }

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(password, salt);

      // Create user
      const user = new User({
        username,
        email,
        passwordHash,
        role: role || 'analyst',
        isActive: true,
      });

      await user.save();

      // Generate JWT
      const token = AuthController._generateToken(user);

      logger.info(`User registered: ${username} (${user._id})`);

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
          },
          token,
        },
      });
    } catch (error) {
      logger.error(`Registration failed: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Login user
   * POST /api/v1/auth/login
   */
  static async login(req, res, next) {
    try {
      const { username, password } = req.body;

      // Find user with password hash
      const user = await User.findOne({ username }).select('+passwordHash');

      if (!user) {
        throw new ApiError(401, 'Invalid credentials');
      }

      // Check if user is active
      if (!user.isActive) {
        throw new ApiError(403, 'Account is disabled');
      }

      // Verify password
      const isValid = await bcrypt.compare(password, user.passwordHash);
      if (!isValid) {
        throw new ApiError(401, 'Invalid credentials');
      }

      // Update last login
      user.lastLogin = new Date();
      await user.save();

      // Generate JWT
      const token = AuthController._generateToken(user);

      logger.info(`User logged in: ${username} (${user._id})`);

      res.status(200).json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
          },
          token,
        },
      });
    } catch (error) {
      logger.error(`Login failed: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get current user profile
   * GET /api/v1/auth/me
   */
  static async getMe(req, res, next) {
    try {
      const user = await User.findById(req.user.id);

      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      res.status(200).json({
        success: true,
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
            isActive: user.isActive,
            lastLogin: user.lastLogin,
            createdAt: user.createdAt,
            preferences: user.preferences,
          },
        },
      });
    } catch (error) {
      logger.error(`Failed to get user: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Update user profile
   * PUT /api/v1/auth/me
   */
  static async updateMe(req, res, next) {
    try {
      const { email, preferences } = req.body;
      const userId = req.user.id;

      const user = await User.findById(userId);
      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      // Update fields
      if (email) user.email = email;
      if (preferences) user.preferences = preferences;

      await user.save();

      logger.info(`User updated: ${user.username} (${user._id})`);

      res.status(200).json({
        success: true,
        message: 'Profile updated successfully',
        data: {
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role,
            preferences: user.preferences,
          },
        },
      });
    } catch (error) {
      logger.error(`Failed to update user: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Change password
   * PUT /api/v1/auth/change-password
   */
  static async changePassword(req, res, next) {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.user.id;

      // Get user with password hash
      const user = await User.findById(userId).select('+passwordHash');
      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      // Verify current password
      const isValid = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!isValid) {
        throw new ApiError(401, 'Current password is incorrect');
      }

      // Hash new password
      const salt = await bcrypt.genSalt(10);
      user.passwordHash = await bcrypt.hash(newPassword, salt);
      await user.save();

      logger.info(`Password changed for user: ${user.username}`);

      res.status(200).json({
        success: true,
        message: 'Password changed successfully',
      });
    } catch (error) {
      logger.error(`Failed to change password: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Logout user
   * POST /api/v1/auth/logout
   */
  static async logout(req, res, next) {
    try {
      logger.info(`User logged out: ${req.user.username}`);

      res.status(200).json({
        success: true,
        message: 'Logout successful',
      });
    } catch (error) {
      logger.error(`Logout failed: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Refresh token
   * POST /api/v1/auth/refresh
   */
  static async refreshToken(req, res, next) {
    try {
      const user = await User.findById(req.user.id);
      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      const token = AuthController._generateToken(user);

      res.status(200).json({
        success: true,
        data: { token },
      });
    } catch (error) {
      logger.error(`Token refresh failed: ${error.message}`, { error });
      next(error);
    }
  }
}

module.exports = AuthController;