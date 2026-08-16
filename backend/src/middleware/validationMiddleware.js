const { ApiError } = require('./errorMiddleware');
const logger = require('../utils/logger');

/**
 * Validation schemas for different endpoints
 */
const schemas = {
  // Auth schemas
  register: {
    username: {
      required: true,
      type: 'string',
      minLength: 3,
      maxLength: 30,
      pattern: /^[a-zA-Z0-9_]+$/,
      message: 'Username must be 3-30 characters and contain only letters, numbers, and underscores',
    },
    email: {
      required: true,
      type: 'string',
      pattern: /^\S+@\S+\.\S+$/,
      message: 'Please provide a valid email address',
    },
    password: {
      required: true,
      type: 'string',
      minLength: 8,
      message: 'Password must be at least 8 characters long',
    },
    role: {
      required: false,
      type: 'string',
      enum: ['analyst', 'viewer'],
    },
  },

  login: {
    username: {
      required: true,
      type: 'string',
      minLength: 1,
    },
    password: {
      required: true,
      type: 'string',
      minLength: 1,
    },
  },

  changePassword: {
    currentPassword: {
      required: true,
      type: 'string',
      minLength: 1,
    },
    newPassword: {
      required: true,
      type: 'string',
      minLength: 8,
      message: 'Password must be at least 8 characters long',
    },
  },

  updateProfile: {
    email: {
      required: false,
      type: 'string',
      pattern: /^\S+@\S+\.\S+$/,
      message: 'Please provide a valid email address',
    },
    preferences: {
      required: false,
      type: 'object',
    },
  },

  // Sample schemas
  updateStatus: {
    status: {
      required: true,
      type: 'string',
      enum: ['pending', 'processing', 'completed', 'failed'],
    },
  },

  // Analysis schemas
  startAnalysis: {
    sampleId: {
      required: true,
      type: 'string',
      pattern: /^[a-fA-F0-9]{24}$/,
      message: 'Invalid sample ID format',
    },
    runDynamic: {
      required: false,
      type: 'boolean',
    },
    runVirusTotal: {
      required: false,
      type: 'boolean',
    },
  },

  // Report schemas
  generateReport: {
    format: {
      required: false,
      type: 'string',
      enum: ['json', 'csv', 'pdf', 'html'],
      default: 'json',
    },
  },

  // Search schemas
  search: {
    query: {
      required: true,
      type: 'string',
      minLength: 1,
      maxLength: 255,
    },
    page: {
      required: false,
      type: 'number',
      min: 1,
      default: 1,
    },
    limit: {
      required: false,
      type: 'number',
      min: 1,
      max: 100,
      default: 20,
    },
  },

  // IOC update
  updateIOC: {
    confidence: {
      required: false,
      type: 'number',
      min: 0,
      max: 1,
    },
    severity: {
      required: false,
      type: 'string',
      enum: ['low', 'medium', 'high', 'critical'],
    },
    notes: {
      required: false,
      type: 'string',
      maxLength: 1000,
    },
    tags: {
      required: false,
      type: 'array',
      items: 'string',
    },
    isActive: {
      required: false,
      type: 'boolean',
    },
  },
};

/**
 * Validate request body against schema
 * @param {string} schemaName - Name of the schema to validate against
 */
const validate = (schemaName) => {
  return (req, res, next) => {
    try {
      const schema = schemas[schemaName];
      if (!schema) {
        throw new Error(`Validation schema not found: ${schemaName}`);
      }

      const errors = [];
      const data = req.body;

      // Check required fields and validate types
      for (const [field, rules] of Object.entries(schema)) {
        const value = data[field];

        // Check required
        if (rules.required && (value === undefined || value === null || value === '')) {
          errors.push(`${field} is required`);
          continue;
        }

        // Skip validation for optional fields that are not present
        if (!rules.required && (value === undefined || value === null || value === '')) {
          continue;
        }

        // Validate type
        if (rules.type) {
          switch (rules.type) {
            case 'string':
              if (typeof value !== 'string') {
                errors.push(`${field} must be a string`);
              }
              break;
            case 'number':
              if (typeof value !== 'number' || isNaN(value)) {
                errors.push(`${field} must be a number`);
              }
              break;
            case 'boolean':
              if (typeof value !== 'boolean') {
                errors.push(`${field} must be a boolean`);
              }
              break;
            case 'object':
              if (typeof value !== 'object' || value === null || Array.isArray(value)) {
                errors.push(`${field} must be an object`);
              }
              break;
            case 'array':
              if (!Array.isArray(value)) {
                errors.push(`${field} must be an array`);
              }
              break;
          }
        }

        // Validate minLength
        if (rules.minLength && typeof value === 'string' && value.length < rules.minLength) {
          errors.push(rules.message || `${field} must be at least ${rules.minLength} characters`);
        }

        // Validate maxLength
        if (rules.maxLength && typeof value === 'string' && value.length > rules.maxLength) {
          errors.push(`${field} must not exceed ${rules.maxLength} characters`);
        }

        // Validate pattern
        if (rules.pattern && typeof value === 'string' && !rules.pattern.test(value)) {
          errors.push(rules.message || `${field} has invalid format`);
        }

        // Validate enum
        if (rules.enum && !rules.enum.includes(value)) {
          errors.push(`${field} must be one of: ${rules.enum.join(', ')}`);
        }

        // Validate number min/max
        if (rules.type === 'number') {
          if (rules.min !== undefined && value < rules.min) {
            errors.push(`${field} must be at least ${rules.min}`);
          }
          if (rules.max !== undefined && value > rules.max) {
            errors.push(`${field} must not exceed ${rules.max}`);
          }
        }

        // Validate array items
        if (rules.type === 'array' && rules.items) {
          for (const item of value) {
            if (typeof item !== rules.items) {
              errors.push(`${field} items must be of type ${rules.items}`);
              break;
            }
          }
        }
      }

      if (errors.length > 0) {
        throw new ApiError(400, 'Validation failed', errors);
      }

      // Sanitize data (remove leading/trailing whitespace from strings)
      for (const [field, value] of Object.entries(data)) {
        if (typeof value === 'string') {
          req.body[field] = value.trim();
        }
      }

      next();
    } catch (error) {
      if (error instanceof ApiError) {
        next(error);
      } else {
        logger.error(`Validation error: ${error.message}`, { error });
        next(new ApiError(400, 'Validation failed'));
      }
    }
  };
};

/**
 * Validate query parameters
 * @param {Object} rules - Query parameter validation rules
 */
const validateQuery = (rules) => {
  return (req, res, next) => {
    try {
      const errors = [];
      const query = req.query;

      for (const [field, rule] of Object.entries(rules)) {
        const value = query[field];

        if (rule.required && (value === undefined || value === null || value === '')) {
          errors.push(`${field} is required`);
          continue;
        }

        if (!rule.required && (value === undefined || value === null || value === '')) {
          continue;
        }

        // Parse type
        let parsedValue = value;
        if (rule.type === 'number') {
          parsedValue = parseInt(value, 10);
          if (isNaN(parsedValue)) {
            errors.push(`${field} must be a number`);
            continue;
          }
          if (rule.min !== undefined && parsedValue < rule.min) {
            errors.push(`${field} must be at least ${rule.min}`);
          }
          if (rule.max !== undefined && parsedValue > rule.max) {
            errors.push(`${field} must not exceed ${rule.max}`);
          }
        }

        if (rule.type === 'boolean') {
          if (value === 'true' || value === '1') {
            req.query[field] = true;
          } else if (value === 'false' || value === '0') {
            req.query[field] = false;
          } else {
            errors.push(`${field} must be a boolean (true/false)`);
          }
        }

        if (rule.enum && !rule.enum.includes(value)) {
          errors.push(`${field} must be one of: ${rule.enum.join(', ')}`);
        }
      }

      if (errors.length > 0) {
        throw new ApiError(400, 'Query validation failed', errors);
      }

      next();
    } catch (error) {
      if (error instanceof ApiError) {
        next(error);
      } else {
        logger.error(`Query validation error: ${error.message}`, { error });
        next(new ApiError(400, 'Query validation failed'));
      }
    }
  };
};

/**
 * Sanitize request body
 * Remove potentially dangerous characters
 */
const sanitize = (req, res, next) => {
  try {
    const sanitizeString = (str) => {
      if (typeof str !== 'string') return str;
      // Remove potential XSS/HTML injection
      return str
        .replace(/[<>]/g, '') // Remove < and >
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
    };

    const sanitizeObject = (obj) => {
      if (!obj || typeof obj !== 'object') return obj;
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string') {
          obj[key] = sanitizeString(value);
        } else if (typeof value === 'object' && value !== null) {
          sanitizeObject(value);
        }
      }
      return obj;
    };

    if (req.body) {
      sanitizeObject(req.body);
    }

    if (req.query) {
      sanitizeObject(req.query);
    }

    if (req.params) {
      sanitizeObject(req.params);
    }

    next();
  } catch (error) {
    logger.error(`Sanitization error: ${error.message}`, { error });
    next();
  }
};

module.exports = {
  validate,
  validateQuery,
  sanitize,
  schemas,
};