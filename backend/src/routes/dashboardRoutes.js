const express = require('express');
const router = express.Router();
const DashboardController = require('../controllers/dashboardController');
const { authenticate } = require('../middleware/authMiddleware');

/**
 * @route   GET /api/v1/dashboard/stats
 * @desc    Get dashboard statistics
 * @access  Private
 */
router.get(
  '/stats',
  authenticate,
  DashboardController.getStats
);

/**
 * @route   GET /api/v1/dashboard/timeline
 * @desc    Get dashboard timeline
 * @access  Private
 */
router.get(
  '/timeline',
  authenticate,
  DashboardController.getTimeline
);

/**
 * @route   GET /api/v1/dashboard/alerts
 * @desc    Get dashboard alerts
 * @access  Private
 */
router.get(
  '/alerts',
  authenticate,
  DashboardController.getAlerts
);

/**
 * @route   GET /api/v1/dashboard/widgets
 * @desc    Get dashboard widgets data
 * @access  Private
 */
router.get(
  '/widgets',
  authenticate,
  DashboardController.getWidgets
);

/**
 * @route   GET /api/v1/dashboard/daily
 * @desc    Get daily summary
 * @access  Private
 */
router.get(
  '/daily',
  authenticate,
  DashboardController.getDailySummary
);

module.exports = router;