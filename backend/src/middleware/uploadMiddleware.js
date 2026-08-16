const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { ApiError } = require('./errorMiddleware');
const logger = require('../utils/logger');

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(process.cwd(), 'storage', 'uploads', 'temp');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const basename = path.basename(file.originalname, ext);
    const uniqueSuffix = crypto.randomBytes(8).toString('hex');
    const filename = `${basename}-${uniqueSuffix}${ext}`;
    cb(null, filename);
  },
});

// File filter
const fileFilter = (req, file, cb) => {
  // Allow all files for now - we'll validate in the service
  cb(null, true);
};

// Configure multer
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB
    files: 1,
  },
});

// Middleware wrapper with error handling
const uploadMiddleware = {
  /**
   * Single file upload
   */
  single: (fieldName = 'file') => {
    return (req, res, next) => {
      const uploadSingle = upload.single(fieldName);
      uploadSingle(req, res, (err) => {
        if (err instanceof multer.MulterError) {
          if (err.code === 'FILE_TOO_LARGE') {
            return next(new ApiError(413, 'File too large. Maximum size is 100MB.'));
          }
          if (err.code === 'LIMIT_FILE_COUNT') {
            return next(new ApiError(400, 'Too many files uploaded.'));
          }
          if (err.code === 'LIMIT_UNEXPECTED_FILE') {
            return next(new ApiError(400, 'Unexpected field.'));
          }
          return next(new ApiError(400, `Upload error: ${err.message}`));
        }
        if (err) {
          return next(err);
        }
        
        // Log file info for debugging
        if (req.file) {
          logger.debug(`File uploaded: ${req.file.originalname} (${req.file.size} bytes)`);
        } else {
          logger.warn('No file received in upload request');
        }
        
        next();
      });
    };
  },

  array: (fieldName = 'files', maxCount = 5) => {
    return (req, res, next) => {
      const uploadArray = upload.array(fieldName, maxCount);
      uploadArray(req, res, (err) => {
        if (err instanceof multer.MulterError) {
          if (err.code === 'FILE_TOO_LARGE') {
            return next(new ApiError(413, 'File too large. Maximum size is 100MB.'));
          }
          if (err.code === 'LIMIT_FILE_COUNT') {
            return next(new ApiError(400, `Too many files. Maximum ${maxCount} files.`));
          }
          return next(new ApiError(400, `Upload error: ${err.message}`));
        }
        if (err) {
          return next(err);
        }
        next();
      });
    };
  },
};

module.exports = { uploadMiddleware };