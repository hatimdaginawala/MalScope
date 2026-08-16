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
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate unique filename with original extension
    const ext = path.extname(file.originalname);
    const basename = path.basename(file.originalname, ext);
    const uniqueSuffix = crypto.randomBytes(8).toString('hex');
    const filename = `${basename}-${uniqueSuffix}${ext}`;
    cb(null, filename);
  },
});

// File filter
const fileFilter = (req, file, cb) => {
  // Define allowed MIME types for PE files and common archives
  const allowedMimeTypes = [
    'application/x-msdownload',
    'application/x-msdos-program',
    'application/x-dosexec',
    'application/vnd.microsoft.portable-executable',
    'application/x-msdos-windows',
    'application/octet-stream',
    'application/x-zip-compressed',
    'application/x-rar-compressed',
    'application/x-7z-compressed',
    'application/gzip',
    'application/x-tar',
  ];

  // Define allowed file extensions
  const allowedExtensions = [
    '.exe', '.dll', '.sys', '.scr', '.com', '.cpl',
    '.zip', '.rar', '.7z', '.gz', '.tar', '.cab',
    '.msi', '.doc', '.docx', '.xls', '.xlsx', '.pdf',
    '.js', '.vbs', '.ps1', '.bat', '.cmd', '.jar',
  ];

  const ext = path.extname(file.originalname).toLowerCase();
  const mimeType = file.mimetype;

  // Check if allowed
  const isValidMime = allowedMimeTypes.includes(mimeType);
  const isValidExt = allowedExtensions.includes(ext);

  if (isValidMime || isValidExt) {
    cb(null, true);
  } else {
    logger.warn(`Rejected file upload: ${file.originalname} (${mimeType})`);
    cb(new ApiError(400, `File type not allowed: ${file.originalname}`));
  }
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
   * Field name: 'file'
   */
  single: (fieldName = 'file') => {
    return (req, res, next) => {
      const uploadSingle = upload.single(fieldName);
      uploadSingle(req, res, (err) => {
        if (err instanceof multer.MulterError) {
          // Multer-specific errors
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
        next();
      });
    };
  },

  /**
   * Multiple file upload
   * Field name: 'files'
   */
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

  /**
   * Handle any file upload with custom validation
   */
  custom: (options = {}) => {
    const customUpload = multer({
      storage: storage,
      fileFilter: options.fileFilter || fileFilter,
      limits: {
        fileSize: options.maxSize || 100 * 1024 * 1024,
        files: options.maxFiles || 1,
      },
    });

    return (req, res, next) => {
      const uploadMethod = options.array
        ? customUpload.array(options.fieldName || 'files', options.maxFiles || 5)
        : customUpload.single(options.fieldName || 'file');

      uploadMethod(req, res, (err) => {
        if (err instanceof multer.MulterError) {
          if (err.code === 'FILE_TOO_LARGE') {
            return next(new ApiError(413, `File too large. Maximum size is ${(options.maxSize || 100 * 1024 * 1024) / 1024 / 1024}MB.`));
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

// Clean up temp files middleware
const cleanupTempFiles = async (req, res, next) => {
  try {
    const tempDir = path.join(process.cwd(), 'storage', 'uploads', 'temp');
    if (fs.existsSync(tempDir)) {
      const files = fs.readdirSync(tempDir);
      const now = Date.now();
      const maxAge = 24 * 60 * 60 * 1000; // 24 hours

      for (const file of files) {
        const filePath = path.join(tempDir, file);
        const stats = fs.statSync(filePath);
        if (now - stats.mtimeMs > maxAge) {
          fs.unlinkSync(filePath);
          logger.debug(`Cleaned up temp file: ${file}`);
        }
      }
    }
    next();
  } catch (error) {
    logger.warn(`Temp file cleanup error: ${error.message}`);
    next(); // Don't block the request
  }
};

module.exports = {
  uploadMiddleware,
  cleanupTempFiles,
};