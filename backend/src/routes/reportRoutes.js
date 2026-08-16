const express = require('express');
const router = express.Router();
const ReportController = require('../controllers/reportController');
const { authenticate, authorize } = require('../middleware/authMiddleware');

/**
 * @route   GET /api/v1/reports/formats
 * @desc    Get available report formats
 * @access  Private
 */
router.get(
  '/formats',
  authenticate,
  ReportController.getFormats
);

/**
 * @route   POST /api/v1/reports/:analysisId
 * @desc    Generate report for an analysis
 * @access  Private
 */
router.post(
  '/:analysisId',
  authenticate,
  ReportController.generateReport
);

/**
 * @route   GET /api/v1/reports/:analysisId
 * @desc    Get report for an analysis
 * @access  Private
 */
router.get(
  '/:analysisId',
  authenticate,
  ReportController.getReport
);

/**
 * @route   GET /api/v1/reports/:analysisId/summary
 * @desc    Get report summary
 * @access  Private
 */
router.get(
  '/:analysisId/summary',
  authenticate,
  ReportController.getReportSummary
);

/**
 * @route   GET /api/v1/reports/:analysisId/exists
 * @desc    Check if report exists
 * @access  Private
 */
router.get(
  '/:analysisId/exists',
  authenticate,
  ReportController.reportExists
);

/**
 * @route   GET /api/v1/reports/:analysisId/download/json
 * @desc    Download report as JSON
 * @access  Private
 */
router.get(
  '/:analysisId/download/json',
  authenticate,
  ReportController.downloadJSON
);

/**
 * @route   GET /api/v1/reports/:analysisId/download/csv
 * @desc    Download report as CSV
 * @access  Private
 */
router.get(
  '/:analysisId/download/csv',
  authenticate,
  ReportController.downloadCSV
);

module.exports = router;