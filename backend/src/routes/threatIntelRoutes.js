const express = require('express');
const router = express.Router();
const ThreatIntelController = require('../controllers/threatIntelController');
const { authenticate, authorize } = require('../middleware/authMiddleware');

// ===== Existing IOC routes =====
router.get('/iocs/search', authenticate, ThreatIntelController.searchIOCs);
router.get('/iocs/stats', authenticate, ThreatIntelController.getIOCStats);
router.get('/iocs/:id', authenticate, ThreatIntelController.getIOC);
router.patch('/iocs/:id', authenticate, authorize(['analyst', 'admin']), ThreatIntelController.updateIOC);
router.delete('/iocs/:id', authenticate, authorize(['admin']), ThreatIntelController.deleteIOC);
router.get('/samples/:sampleId/iocs', authenticate, ThreatIntelController.getIOCsForSample);

// ===== NEW: Configuration Indicators =====
router.get('/config/samples/:sampleId', authenticate, ThreatIntelController.getConfigIndicators);
router.get('/config/search', authenticate, ThreatIntelController.searchConfigIndicators);
router.get('/config/stats', authenticate, ThreatIntelController.getConfigStats);
router.delete('/config/:id', authenticate, authorize(['admin']), ThreatIntelController.deleteConfigIndicator);

// ===== NEW: Similarity =====
router.get('/similarity/samples/:sampleId', authenticate, ThreatIntelController.getSimilarityResults);
router.get('/similarity/related/:sampleId', authenticate, ThreatIntelController.getRelatedSamples);

// ===== NEW: Malware Families =====
router.get('/families', authenticate, ThreatIntelController.listFamilies);
router.get('/families/top', authenticate, ThreatIntelController.getTopFamilies);
router.get('/families/:id', authenticate, ThreatIntelController.getFamilyById);
router.get('/families/name/:name', authenticate, ThreatIntelController.getFamilyByName);
router.get('/families/sample/:sampleId', authenticate, ThreatIntelController.getFamilyForSample);
router.post('/families', authenticate, authorize(['analyst', 'admin']), ThreatIntelController.createFamily);
router.post('/families/:id/sample', authenticate, authorize(['analyst', 'admin']), ThreatIntelController.addSampleToFamily);
router.delete('/families/:id/sample/:sampleId', authenticate, authorize(['admin']), ThreatIntelController.removeSampleFromFamily);
router.delete('/families/:id', authenticate, authorize(['admin']), ThreatIntelController.deleteFamily);

// ===== Existing VirusTotal route =====
router.get('/virustotal/:hash', authenticate, ThreatIntelController.lookupVT);
router.get('/related/:type/:value', authenticate, ThreatIntelController.getRelatedSamples);
router.get('/summary', authenticate, ThreatIntelController.getSummary);

module.exports = router;