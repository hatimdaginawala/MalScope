const express = require('express');
const router = express.Router();
const AnalysisController = require('../controllers/analysisController');
const { authenticate, authorize } = require('../middleware/authMiddleware');
const { validate } = require('../middleware/validationMiddleware');
const { rateLimitMiddleware } = require('../middleware/rateLimitMiddleware');

/**
 * @route   POST /api/v1/analyses
 * @desc    Start a new analysis
 * @access  Private
 */
router.post(
  '/',
  authenticate,
  rateLimitMiddleware({ windowMs: 60 * 60 * 1000, max: 50 }), // 50 per hour
  validate('startAnalysis'),
  AnalysisController.startAnalysis
);

/**
 * @route   GET /api/v1/analyses/stats
 * @desc    Get analysis statistics
 * @access  Private
 */
router.get(
  '/stats',
  authenticate,
  AnalysisController.getStats
);

/**
 * @route   GET /api/v1/analyses/sample/:sampleId
 * @desc    Get analyses for a specific sample
 * @access  Private
 */
router.get(
  '/sample/:sampleId',
  authenticate,
  AnalysisController.getAnalysesForSample
);

/**
 * @route   GET /api/v1/analyses/:id/status
 * @desc    Get analysis status
 * @access  Private
 */
router.get(
  '/:id/status',
  authenticate,
  AnalysisController.getStatus
);

/**
 * @route   GET /api/v1/analyses/:id
 * @desc    Get analysis by ID
 * @access  Private
 */
router.get(
  '/:id',
  authenticate,
  AnalysisController.getAnalysis
);

/**
 * @route   POST /api/v1/analyses/:id/cancel
 * @desc    Cancel an analysis
 * @access  Private
 */
router.post(
  '/:id/cancel',
  authenticate,
  authorize(['analyst', 'admin']),
  AnalysisController.cancelAnalysis
);

module.exports = router;