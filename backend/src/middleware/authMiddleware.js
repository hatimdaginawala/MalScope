const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');
const environment = require('../config/environment');
const { ApiError } = require('./errorMiddleware');

/**
 * Authenticate JWT token
 * Verifies the token and attaches user to req.user
 */
const authenticate = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new ApiError(401, 'No token provided. Please authenticate.');
    }

    const token = authHeader.substring(7); // Remove 'Bearer '

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, environment.jwtSecret);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new ApiError(401, 'Token expired. Please login again.');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new ApiError(401, 'Invalid token. Please login again.');
      }
      throw new ApiError(401, 'Authentication failed.');
    }

    // Get user from database
    const user = await User.findById(decoded.id).select('-passwordHash');
    if (!user) {
      throw new ApiError(401, 'User not found. Please login again.');
    }

    // Check if user is active
    if (!user.isActive) {
      throw new ApiError(403, 'Account is disabled. Please contact administrator.');
    }

    // Attach user to request
    req.user = user;
    req.userId = user._id;

    logger.debug(`User authenticated: ${user.username} (${user._id})`);

    next();
  } catch (error) {
    if (error instanceof ApiError) {
      next(error);
    } else {
      logger.error(`Authentication error: ${error.message}`, { error });
      next(new ApiError(401, 'Authentication failed.'));
    }
  }
};

/**
 * Authorize based on user role
 * @param {string|string[]} roles - Required role(s)
 */
const authorize = (roles) => {
  return (req, res, next) => {
    try {
      if (!req.user) {
        throw new ApiError(401, 'Please authenticate first.');
      }

      const userRole = req.user.role;
      const allowedRoles = Array.isArray(roles) ? roles : [roles];

      // Role hierarchy for admin override
      if (userRole === 'admin') {
        // Admin has access to everything
        return next();
      }

      if (!allowedRoles.includes(userRole)) {
        throw new ApiError(403, `Insufficient permissions. Required roles: ${allowedRoles.join(', ')}`);
      }

      logger.debug(`User authorized: ${req.user.username} (${userRole})`);

      next();
    } catch (error) {
      if (error instanceof ApiError) {
        next(error);
      } else {
        logger.error(`Authorization error: ${error.message}`, { error });
        next(new ApiError(403, 'Authorization failed.'));
      }
    }
  };
};

/**
 * Check if user owns the resource or is admin
 * @param {Function} getResourceOwnerId - Function that returns the owner ID from the request
 */
const checkOwnership = (getResourceOwnerId) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        throw new ApiError(401, 'Please authenticate first.');
      }

      // Admin bypass
      if (req.user.role === 'admin') {
        return next();
      }

      const ownerId = await getResourceOwnerId(req);
      if (!ownerId) {
        throw new ApiError(404, 'Resource not found.');
      }

      if (ownerId.toString() !== req.user._id.toString()) {
        throw new ApiError(403, 'You do not have permission to access this resource.');
      }

      next();
    } catch (error) {
      if (error instanceof ApiError) {
        next(error);
      } else {
        logger.error(`Ownership check error: ${error.message}`, { error });
        next(new ApiError(403, 'Permission denied.'));
      }
    }
  };
};

/**
 * Optional authentication (doesn't require token, but attaches user if present)
 */
const optionalAuthenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // No token, proceed without user
      return next();
    }

    const token = authHeader.substring(7);
    const decoded = jwt.verify(token, environment.jwtSecret);
    const user = await User.findById(decoded.id).select('-passwordHash');

    if (user && user.isActive) {
      req.user = user;
      req.userId = user._id;
    }

    next();
  } catch (error) {
    // Invalid token, but we don't want to block the request
    // Just proceed without user
    next();
  }
};

/**
 * Check API key authentication (for service-to-service)
 */
const authenticateApiKey = (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    const validApiKey = process.env.API_KEY || 'development-api-key';

    if (!apiKey || apiKey !== validApiKey) {
      throw new ApiError(401, 'Invalid or missing API key.');
    }

    // Attach service user
    req.user = {
      id: 'system',
      username: 'system',
      role: 'admin',
      isSystem: true,
    };
    req.userId = 'system';

    next();
  } catch (error) {
    if (error instanceof ApiError) {
      next(error);
    } else {
      logger.error(`API key authentication error: ${error.message}`, { error });
      next(new ApiError(401, 'API key authentication failed.'));
    }
  }
};

module.exports = {
  authenticate,
  authorize,
  checkOwnership,
  optionalAuthenticate,
  authenticateApiKey,
};