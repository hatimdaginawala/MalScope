const express = require('express');
const router = express.Router();
const StaticAnalysisController = require('../controllers/staticAnalysisController');
const { authenticate } = require('../middleware/authMiddleware');

/**
 * @route   GET /api/v1/analyses/:analysisId/static
 * @desc    Get static analysis results
 * @access  Private
 */
router.get(
  '/:analysisId/static',
  authenticate,
  StaticAnalysisController.getResults
);

/**
 * @route   GET /api/v1/analyses/:analysisId/static/summary
 * @desc    Get static analysis summary
 * @access  Private
 */
router.get(
  '/:analysisId/static/summary',
  authenticate,
  StaticAnalysisController.getSummary
);

// ===== API Intelligence Routes =====
/**
 * @route   GET /api/v1/analyses/:analysisId/static/api-intelligence
 * @desc    Get API intelligence results
 * @access  Private
 */
router.get(
  '/:analysisId/static/api-intelligence',
  authenticate,
  StaticAnalysisController.getAPIIntelligence
);

/**
 * @route   GET /api/v1/analyses/:analysisId/static/high-risk-apis
 * @desc    Get high-risk APIs
 * @access  Private
 */
router.get(
  '/:analysisId/static/high-risk-apis',
  authenticate,
  StaticAnalysisController.getHighRiskApis
);

/**
 * @route   GET /api/v1/analyses/:analysisId/static/yara
 * @desc    Get YARA matches
 * @access  Private
 */
router.get(
  '/:analysisId/static/yara',
  authenticate,
  StaticAnalysisController.getYaraMatches
);

/**
 * @route   GET /api/v1/analyses/:analysisId/static/findings
 * @desc    Get static analysis findings
 * @access  Private
 */
router.get(
  '/:analysisId/static/findings',
  authenticate,
  StaticAnalysisController.getFindings
);

/**
 * @route   GET /api/v1/analyses/:analysisId/static/pe-info
 * @desc    Get PE file information
 * @access  Private
 */
router.get(
  '/:analysisId/static/pe-info',
  authenticate,
  StaticAnalysisController.getPEInfo
);

/**
 * @route   GET /api/v1/analyses/:analysisId/static/exists
 * @desc    Check if static analysis exists
 * @access  Private
 */
router.get(
  '/:analysisId/static/exists',
  authenticate,
  StaticAnalysisController.exists
);

/**
 * @route   POST /api/v1/analyses/:analysisId/static/rerun
 * @desc    Rerun static analysis
 * @access  Private (Requires appropriate role)
 */
router.post(
  '/:analysisId/static/rerun',
  authenticate,
  StaticAnalysisController.rerun
);

router.get(
  '/:analysisId/static/string-intelligence',
  authenticate,
  StaticAnalysisController.getStringIntelligence
);
// ===== Resource Analysis Routes =====
router.get(
  '/:analysisId/static/resources/summary',
  authenticate,
  StaticAnalysisController.getResourceSummary
);

router.get(
  '/:analysisId/static/resources/details',
  authenticate,
  StaticAnalysisController.getResourceDetails
);

// ===== Signature Analysis Route =====
router.get(
  '/:analysisId/static/signature',
  authenticate,
  StaticAnalysisController.getSignatureAnalysis
);
module.exports = router;