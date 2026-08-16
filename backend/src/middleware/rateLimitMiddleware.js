const rateLimit = require('express-rate-limit');
const { ApiError } = require('./errorMiddleware');
const logger = require('../utils/logger');

// Store for custom rate limiting by IP
const ipStore = new Map();

/**
 * Default rate limiter
 * 100 requests per 15 minutes
 */
const defaultLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded: ${req.ip} - ${req.method} ${req.path}`);
    res.status(429).json({
      success: false,
      status: 429,
      message: 'Too many requests from this IP, please try again later.',
    });
  },
});

/**
 * Strict rate limiter for authentication
 * 10 requests per 15 minutes
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Auth rate limit exceeded: ${req.ip} - ${req.method} ${req.path}`);
    res.status(429).json({
      success: false,
      status: 429,
      message: 'Too many authentication attempts, please try again later.',
    });
  },
});

/**
 * Strict rate limiter for uploads
 * 20 requests per hour
 */
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: 'Too many uploads from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Upload rate limit exceeded: ${req.ip} - ${req.method} ${req.path}`);
    res.status(429).json({
      success: false,
      status: 429,
      message: 'Too many uploads from this IP, please try again later.',
    });
  },
});

/**
 * Custom rate limiter with configurable options
 * @param {Object} options - Rate limit options
 */
const rateLimitMiddleware = (options = {}) => {
  const windowMs = options.windowMs || 15 * 60 * 1000;
  const max = options.max || 100;
  const key = options.key || 'default';

  return async (req, res, next) => {
    try {
      const ip = req.ip || req.connection.remoteAddress;
      const path = req.path || req.url;
      const identifier = `${key}:${ip}:${path}`;

      const now = Date.now();
      const record = ipStore.get(identifier) || { count: 0, resetTime: now + windowMs };

      // Reset if window expired
      if (now > record.resetTime) {
        record.count = 0;
        record.resetTime = now + windowMs;
      }

      record.count++;

      ipStore.set(identifier, record);

      // Set headers
      res.setHeader('X-RateLimit-Limit', max);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, max - record.count));
      res.setHeader('X-RateLimit-Reset', new Date(record.resetTime).toISOString());

      if (record.count > max) {
        logger.warn(`Rate limit exceeded: ${ip} - ${req.method} ${req.path}`);
        throw new ApiError(429, 'Too many requests, please try again later.');
      }

      next();
    } catch (error) {
      if (error instanceof ApiError) {
        next(error);
      } else {
        logger.error(`Rate limit error: ${error.message}`, { error });
        next(new ApiError(429, 'Rate limit error'));
      }
    }
  };
};

/**
 * Clear rate limit store (useful for testing)
 */
const clearRateLimitStore = () => {
  ipStore.clear();
};

/**
 * Get rate limit status for a client
 */
const getRateLimitStatus = (req) => {
  const ip = req.ip || req.connection.remoteAddress;
  const path = req.path || req.url;
  const identifier = `default:${ip}:${path}`;
  const record = ipStore.get(identifier);

  if (!record) {
    return { remaining: 100, reset: null };
  }

  const remaining = Math.max(0, 100 - record.count);
  return {
    remaining,
    reset: new Date(record.resetTime),
  };
};

/**
 * Clean up expired rate limit entries
 */
const cleanupRateLimitStore = () => {
  const now = Date.now();
  for (const [key, record] of ipStore) {
    if (now > record.resetTime) {
      ipStore.delete(key);
    }
  }
};

// Run cleanup every hour
setInterval(cleanupRateLimitStore, 60 * 60 * 1000);

module.exports = {
  rateLimitMiddleware,
  defaultLimiter,
  authLimiter,
  uploadLimiter,
  clearRateLimitStore,
  getRateLimitStatus,
};