const logger = require('../utils/logger');

// Custom error class for API errors
class ApiError extends Error {
  constructor(statusCode, message, details = null) {
    super(message);
    this.statusCode = statusCode;
    this.details = details;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

// Global error handler
const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  // Log error
  logger.error(`[${req.method}] ${req.path} - ${message}`, {
    statusCode,
    stack: err.stack,
    body: req.body,
    query: req.query,
    params: req.params,
  });

  // Response
  const response = {
    success: false,
    status: statusCode,
    message,
  };

  if (err.details) {
    response.details = err.details;
  }

  // Include stack in development
  if (process.env.NODE_ENV === 'development') {
    response.stack = err.stack;
  }

  res.status(statusCode).json(response);
};

// 404 handler
const notFoundHandler = (req, res, next) => {
  const error = new ApiError(404, `Route not found: ${req.method} ${req.path}`);
  next(error);
};

module.exports = {
  ApiError,
  errorHandler,
  notFoundHandler,
};