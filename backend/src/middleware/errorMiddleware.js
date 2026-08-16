const logger = require('../utils/logger');

/**
 * Custom API Error class
 * Extends built-in Error with HTTP status code and details
 */
class ApiError extends Error {
  constructor(statusCode, message, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.details = details;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();
    Error.captureStackTrace(this, this.constructor);
  }

  /**
   * Create a 400 Bad Request error
   */
  static badRequest(message = 'Bad request', details = null) {
    return new ApiError(400, message, details);
  }

  /**
   * Create a 401 Unauthorized error
   */
  static unauthorized(message = 'Unauthorized', details = null) {
    return new ApiError(401, message, details);
  }

  /**
   * Create a 403 Forbidden error
   */
  static forbidden(message = 'Forbidden', details = null) {
    return new ApiError(403, message, details);
  }

  /**
   * Create a 404 Not Found error
   */
  static notFound(message = 'Resource not found', details = null) {
    return new ApiError(404, message, details);
  }

  /**
   * Create a 409 Conflict error
   */
  static conflict(message = 'Resource conflict', details = null) {
    return new ApiError(409, message, details);
  }

  /**
   * Create a 422 Unprocessable Entity error
   */
  static unprocessable(message = 'Unprocessable entity', details = null) {
    return new ApiError(422, message, details);
  }

  /**
   * Create a 429 Too Many Requests error
   */
  static tooManyRequests(message = 'Too many requests', details = null) {
    return new ApiError(429, message, details);
  }

  /**
   * Create a 500 Internal Server Error
   */
  static internal(message = 'Internal server error', details = null) {
    return new ApiError(500, message, details);
  }

  /**
   * Create a 503 Service Unavailable error
   */
  static serviceUnavailable(message = 'Service unavailable', details = null) {
    return new ApiError(503, message, details);
  }
}

/**
 * Global error handler middleware
 */
const errorHandler = (err, req, res, next) => {
  // Log the error
  const errorLog = {
    message: err.message,
    statusCode: err.statusCode || 500,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userId: req.userId,
    query: req.query,
    params: req.params,
    body: req.body,
    timestamp: new Date().toISOString(),
  };

  if (err.statusCode >= 500) {
    logger.error(`[${req.method}] ${req.path} - ${err.message}`, errorLog);
  } else {
    logger.warn(`[${req.method}] ${req.path} - ${err.message}`, errorLog);
  }

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const details = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({
      success: false,
      status: 400,
      message: 'Validation error',
      details,
      timestamp: new Date().toISOString(),
    });
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern)[0];
    return res.status(409).json({
      success: false,
      status: 409,
      message: `Duplicate value for ${field}`,
      details: [`${field} already exists`],
      timestamp: new Date().toISOString(),
    });
  }

  // Mongoose cast error (invalid ID)
  if (err.name === 'CastError') {
    return res.status(400).json({
      success: false,
      status: 400,
      message: 'Invalid ID format',
      details: [`${err.path} is not a valid ID`],
      timestamp: new Date().toISOString(),
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      status: 401,
      message: 'Invalid token',
      timestamp: new Date().toISOString(),
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      status: 401,
      message: 'Token expired',
      timestamp: new Date().toISOString(),
    });
  }

  // Multer errors
  if (err.name === 'MulterError') {
    const messages = {
      'LIMIT_PART_COUNT': 'Too many parts',
      'LIMIT_FILE_SIZE': 'File too large',
      'LIMIT_FILE_COUNT': 'Too many files',
      'LIMIT_FIELD_KEY': 'Field name too long',
      'LIMIT_FIELD_VALUE': 'Field value too long',
      'LIMIT_FIELD_COUNT': 'Too many fields',
      'LIMIT_UNEXPECTED_FILE': 'Unexpected file field',
    };
    return res.status(400).json({
      success: false,
      status: 400,
      message: messages[err.code] || 'Upload error',
      details: [err.message],
      timestamp: new Date().toISOString(),
    });
  }

  // API Error (our custom error)
  if (err instanceof ApiError) {
    const response = {
      success: false,
      status: err.statusCode,
      message: err.message,
      timestamp: err.timestamp,
    };

    if (err.details) {
      response.details = err.details;
    }

    // Include stack trace in development
    if (process.env.NODE_ENV === 'development') {
      response.stack = err.stack;
    }

    return res.status(err.statusCode).json(response);
  }

  // Default error response
  const statusCode = err.statusCode || 500;
  const response = {
    success: false,
    status: statusCode,
    message: err.message || 'Internal server error',
    timestamp: new Date().toISOString(),
  };

  if (process.env.NODE_ENV === 'development') {
    response.stack = err.stack;
    response.details = err.details;
  }

  res.status(statusCode).json(response);
};

/**
 * 404 Not Found handler
 */
const notFoundHandler = (req, res, next) => {
  const error = new ApiError(404, `Route not found: ${req.method} ${req.originalUrl}`);
  next(error);
};

/**
 * Async handler wrapper to catch errors in async route handlers
 * @param {Function} fn - Async function to wrap
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Request timeout handler
 * @param {number} ms - Timeout in milliseconds
 */
const timeoutHandler = (ms) => {
  return (req, res, next) => {
    const timeout = setTimeout(() => {
      const error = new ApiError(408, 'Request timeout');
      next(error);
    }, ms);

    // Clear timeout on response finish
    res.on('finish', () => {
      clearTimeout(timeout);
    });

    next();
  };
};

/**
 * CORS error handler for preflight requests
 */
const corsErrorHandler = (err, req, res, next) => {
  if (err.name === 'CorsError') {
    return res.status(403).json({
      success: false,
      status: 403,
      message: 'CORS error',
      details: [err.message],
      timestamp: new Date().toISOString(),
    });
  }
  next(err);
};

/**
 * Handle uncaught exceptions
 */
const uncaughtExceptionHandler = (err) => {
  logger.error('Uncaught Exception:', {
    error: err.message,
    stack: err.stack,
    timestamp: new Date().toISOString(),
  });
  process.exit(1);
};

/**
 * Handle unhandled rejections
 */
const unhandledRejectionHandler = (reason, promise) => {
  logger.error('Unhandled Rejection:', {
    reason: reason,
    promise: promise,
    timestamp: new Date().toISOString(),
  });
};

// Register global error handlers
process.on('uncaughtException', uncaughtExceptionHandler);
process.on('unhandledRejection', unhandledRejectionHandler);

module.exports = {
  ApiError,
  errorHandler,
  notFoundHandler,
  asyncHandler,
  timeoutHandler,
  corsErrorHandler,
};