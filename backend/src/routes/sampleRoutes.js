const express = require('express');
const router = express.Router();
const SampleController = require('../controllers/sampleController');
const { authenticate, authorize } = require('../middleware/authMiddleware');
const { uploadMiddleware } = require('../middleware/uploadMiddleware');
const { validate } = require('../middleware/validationMiddleware');
const { rateLimitMiddleware } = require('../middleware/rateLimitMiddleware');

/**
 * @route   POST /api/v1/samples
 * @desc    Upload a new sample
 * @access  Private (Authenticated users)
 */
router.post(
  '/',
  authenticate,
  uploadMiddleware.single('file'),
  rateLimitMiddleware({ windowMs: 60 * 60 * 1000, max: 20 }),
  SampleController.upload
);

/**
 * @route   GET /api/v1/samples/search
 * @desc    Search samples
 * @access  Private
 */
router.get(
  '/search',
  authenticate,
  SampleController.search
);

/**
 * @route   GET /api/v1/samples/stats
 * @desc    Get sample statistics
 * @access  Private
 */
router.get(
  '/stats',
  authenticate,
  SampleController.getStats
);

/**
 * @route   GET /api/v1/samples/hash/:hash
 * @desc    Get sample by hash
 * @access  Private
 */
router.get(
  '/hash/:hash',
  authenticate,
  SampleController.getSampleByHash
);

/**
 * @route   POST /api/v1/samples/:id/tags
 * @desc    Add tags to sample
 * @access  Private
 */
router.post(
  '/:id/tags',
  authenticate,
  authorize(['analyst', 'admin']),
  validate('addTags'),
  SampleController.addTags
);

/**
 * @route   DELETE /api/v1/samples/:id/tags
 * @desc    Remove tags from sample
 * @access  Private
 */
router.delete(
  '/:id/tags',
  authenticate,
  authorize(['analyst', 'admin']),
  validate('removeTags'),
  SampleController.removeTags
);

/**
 * @route   GET /api/v1/samples/:id
 * @desc    Get sample by ID
 * @access  Private
 */
router.get(
  '/:id',
  authenticate,
  SampleController.getSample
);

/**
 * @route   GET /api/v1/samples/:id/download
 * @desc    Download sample file
 * @access  Private
 */
router.get(
  '/:id/download',
  authenticate,
  authorize(['analyst', 'admin']),
  SampleController.downloadSample
);

/**
 * @route   PATCH /api/v1/samples/:id/status
 * @desc    Update sample status
 * @access  Private (Admin only)
 */
router.patch(
  '/:id/status',
  authenticate,
  authorize(['admin']),
  validate('updateStatus'),
  SampleController.updateStatus
);

/**
 * @route   DELETE /api/v1/samples/:id
 * @desc    Delete sample
 * @access  Private (Admin only)
 */
router.delete(
  '/:id',
  authenticate,
  authorize(['admin']),
  SampleController.deleteSample
);

/**
 * @route   GET /api/v1/samples
 * @desc    Get all samples with pagination
 * @access  Private
 */
router.get(
  '/',
  authenticate,
  SampleController.getSamples
);

module.exports = router;