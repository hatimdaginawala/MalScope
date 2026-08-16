const express = require('express');
const router = express.Router();
const DynamicAnalysisController = require('../controllers/dynamicAnalysisController');
const { authenticate, authorize } = require('../middleware/authMiddleware');

/**
 * @route   GET /api/v1/analyses/:analysisId/dynamic
 * @desc    Get dynamic analysis results
 * @access  Private
 */
router.get(
  '/:analysisId/dynamic',
  authenticate,
  DynamicAnalysisController.getResults
);

/**
 * @route   GET /api/v1/analyses/:analysisId/dynamic/summary
 * @desc    Get dynamic analysis summary
 * @access  Private
 */
router.get(
  '/:analysisId/dynamic/summary',
  authenticate,
  DynamicAnalysisController.getSummary
);

/**
 * @route   GET /api/v1/analyses/:analysisId/dynamic/processes
 * @desc    Get process activity
 * @access  Private
 */
router.get(
  '/:analysisId/dynamic/processes',
  authenticate,
  DynamicAnalysisController.getProcesses
);

/**
 * @route   GET /api/v1/analyses/:analysisId/dynamic/network
 * @desc    Get network activity
 * @access  Private
 */
router.get(
  '/:analysisId/dynamic/network',
  authenticate,
  DynamicAnalysisController.getNetworkEvents
);

/**
 * @route   GET /api/v1/analyses/:analysisId/dynamic/files
 * @desc    Get file activity
 * @access  Private
 */
router.get(
  '/:analysisId/dynamic/files',
  authenticate,
  DynamicAnalysisController.getFileEvents
);

/**
 * @route   GET /api/v1/analyses/:analysisId/dynamic/registry
 * @desc    Get registry activity
 * @access  Private
 */
router.get(
  '/:analysisId/dynamic/registry',
  authenticate,
  DynamicAnalysisController.getRegistryEvents
);

/**
 * @route   GET /api/v1/analyses/:analysisId/dynamic/persistence
 * @desc    Get persistence mechanisms
 * @access  Private
 */
router.get(
  '/:analysisId/dynamic/persistence',
  authenticate,
  DynamicAnalysisController.getPersistence
);

/**
 * @route   GET /api/v1/analyses/:analysisId/dynamic/behaviors
 * @desc    Get behavioral findings
 * @access  Private
 */
router.get(
  '/:analysisId/dynamic/behaviors',
  authenticate,
  DynamicAnalysisController.getBehaviors
);

/**
 * @route   GET /api/v1/analyses/:analysisId/dynamic/exists
 * @desc    Check if dynamic analysis exists
 * @access  Private
 */
router.get(
  '/:analysisId/dynamic/exists',
  authenticate,
  DynamicAnalysisController.exists
);

/**
 * @route   POST /api/v1/analyses/:analysisId/dynamic/rerun
 * @desc    Rerun dynamic analysis
 * @access  Private (Requires appropriate role)
 */
router.post(
  '/:analysisId/dynamic/rerun',
  authenticate,
  authorize(['analyst', 'admin']),
  DynamicAnalysisController.rerun
);

/**
 * @route   GET /api/v1/dynamic/vm-status
 * @desc    Get VM status
 * @access  Private
 */
router.get(
  '/dynamic/vm-status',
  authenticate,
  DynamicAnalysisController.getVMStatus
);

module.exports = router;