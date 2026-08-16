const express = require('express');
const router = express.Router();
const ThreatIntelController = require('../controllers/threatIntelController');
const { authenticate, authorize } = require('../middleware/authMiddleware');

/**
 * @route   GET /api/v1/threat-intel/iocs/search
 * @desc    Search IOCs
 * @access  Private
 */
router.get(
  '/iocs/search',
  authenticate,
  ThreatIntelController.searchIOCs
);

/**
 * @route   GET /api/v1/threat-intel/iocs/stats
 * @desc    Get IOC statistics
 * @access  Private
 */
router.get(
  '/iocs/stats',
  authenticate,
  ThreatIntelController.getIOCStats
);

/**
 * @route   GET /api/v1/threat-intel/iocs/:id
 * @desc    Get IOC by ID
 * @access  Private
 */
router.get(
  '/iocs/:id',
  authenticate,
  ThreatIntelController.getIOC
);

/**
 * @route   PATCH /api/v1/threat-intel/iocs/:id
 * @desc    Update IOC
 * @access  Private (Requires appropriate role)
 */
router.patch(
  '/iocs/:id',
  authenticate,
  authorize(['analyst', 'admin']),
  ThreatIntelController.updateIOC
);

/**
 * @route   DELETE /api/v1/threat-intel/iocs/:id
 * @desc    Delete IOC
 * @access  Private (Admin only)
 */
router.delete(
  '/iocs/:id',
  authenticate,
  authorize(['admin']),
  ThreatIntelController.deleteIOC
);

/**
 * @route   GET /api/v1/threat-intel/samples/:sampleId/iocs
 * @desc    Get IOCs for a sample
 * @access  Private
 */
router.get(
  '/samples/:sampleId/iocs',
  authenticate,
  ThreatIntelController.getIOCsForSample
);

/**
 * @route   GET /api/v1/threat-intel/virustotal/:hash
 * @desc    Lookup hash in VirusTotal
 * @access  Private
 */
router.get(
  '/virustotal/:hash',
  authenticate,
  ThreatIntelController.lookupVT
);

/**
 * @route   GET /api/v1/threat-intel/related/:type/:value
 * @desc    Get related samples by IOC
 * @access  Private
 */
router.get(
  '/related/:type/:value',
  authenticate,
  ThreatIntelController.getRelatedSamples
);

/**
 * @route   GET /api/v1/threat-intel/summary
 * @desc    Get threat intelligence summary
 * @access  Private
 */
router.get(
  '/summary',
  authenticate,
  ThreatIntelController.getSummary
);

module.exports = router;