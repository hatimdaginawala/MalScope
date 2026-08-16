const MalwareSample = require('../models/MalwareSample');
const AnalysisService = require('./analysisService');
const StaticAnalysisService = require('./staticAnalysisService');
const DynamicAnalysisService = require('./dynamicAnalysisService');
const IOCService = require('./iocService');
const RiskService = require('./riskService');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class ReportService {
  /**
   * Generate comprehensive report for an analysis
   */
  static async generateReport(analysisId) {
    try {
      // Get analysis with all related data
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      // Get sample
      const sample = await MalwareSample.findById(analysis.sample).lean();
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      // Get static analysis results
      let staticResults = null;
      if (analysis.staticAnalysis) {
        staticResults = await StaticAnalysisService.getResults(analysisId);
      }

      // Get dynamic analysis results
      let dynamicResults = null;
      if (analysis.dynamicAnalysis) {
        dynamicResults = await DynamicAnalysisService.getResults(analysisId);
      }

      // Get IOCs
      const iocs = await IOCService.getIOCsForSample(sample._id);

      // Get assessment
      let assessment = null;
      if (analysis.threatAssessment) {
        assessment = await RiskService.getRiskSummary(analysis.threatAssessment);
      }

      // Build comprehensive report
      const report = {
        // Section 1: Sample Information
        sampleInfo: {
          filename: sample.filename,
          originalFilename: sample.originalFilename,
          sha256: sample.sha256,
          md5: sample.md5,
          sha1: sample.sha1,
          fileSize: sample.fileSize,
          fileType: sample.fileType,
          peType: sample.peType,
          arch: sample.arch,
          submittedAt: sample.createdAt,
          tags: sample.tags || [],
        },

        // Section 2: Analysis Overview
        analysisInfo: {
          analysisId: analysis._id,
          status: analysis.status,
          startedAt: analysis.startedAt,
          completedAt: analysis.completedAt,
          duration: analysis.duration,
          environment: analysis.environment,
          logs: analysis.logs || [],
        },

        // Section 3: Static Analysis
        staticAnalysis: staticResults ? {
          fileInfo: staticResults.fileInfo,
          sections: staticResults.sections || [],
          imports: staticResults.imports || [],
          exports: staticResults.exports || [],
          strings: staticResults.strings || {},
          entropy: staticResults.entropy || {},
          resources: staticResults.resources || [],
          yaraMatches: staticResults.yaraMatches || [],
          findings: staticResults.findings || [],
          warnings: staticResults.warnings || [],
          errors: staticResults.errors || [],
          processedAt: staticResults.processedAt,
        } : null,

        // Section 4: Dynamic Analysis
        dynamicAnalysis: dynamicResults ? {
          environment: dynamicResults.environment || {},
          processes: dynamicResults.processes || [],
          fileEvents: dynamicResults.fileEvents || [],
          registryEvents: dynamicResults.registryEvents || [],
          persistence: dynamicResults.persistence || [],
          networkEvents: dynamicResults.networkEvents || [],
          behaviors: dynamicResults.behaviors || [],
          execution: dynamicResults.execution || {},
          warnings: dynamicResults.warnings || [],
          errors: dynamicResults.errors || [],
          processedAt: dynamicResults.processedAt,
        } : null,

        // Section 5: IOCs
        iocs: {
          total: iocs.total || 0,
          items: (iocs.iocs || []).map(ioc => ({
            type: ioc.type,
            value: ioc.value,
            severity: ioc.severity,
            confidence: ioc.confidence,
            source: ioc.source,
            tags: ioc.tags || [],
            firstSeen: ioc.firstSeen,
            lastSeen: ioc.lastSeen,
          })),
        },

        // Section 6: Risk Assessment
        riskAssessment: assessment ? {
          score: assessment.score,
          level: assessment.level,
          verdict: assessment.verdict,
          confidence: assessment.confidence,
          contributors: assessment.contributors || [],
          keyFindings: assessment.keyFindings || [],
          explanation: assessment.explanation || {},
          timestamp: assessment.timestamp,
        } : null,

        // Section 7: Final Verdict
        finalVerdict: {
          classification: assessment ? assessment.verdict : 'not_analyzed',
          riskLevel: assessment ? assessment.level : 'unknown',
          confidence: assessment ? assessment.confidence : 0,
          summary: this._generateVerdictSummary(assessment),
        },

        // Section 8: Summary
        summary: {
          threatIntelligence: {
            hasVirusTotal: !!analysis.virusTotalReport,
            detectionCount: analysis.virusTotalReport ? 
              analysis.virusTotalReport.stats?.malicious || 0 : 0,
          },
          statistics: {
            totalIOCs: iocs.total || 0,
            behavioralFindings: dynamicResults?.behaviors?.length || 0,
            staticFindings: staticResults?.findings?.length || 0,
            yaraMatches: staticResults?.yaraMatches?.length || 0,
          },
          recommendations: this._generateRecommendations(assessment, staticResults, dynamicResults),
        },

        // Metadata
        metadata: {
          reportGeneratedAt: new Date().toISOString(),
          reportVersion: '1.0.0',
          analysisVersion: analysis.analysisVersion || '1.0.0',
          generatedBy: 'MalScope',
        },
      };

      logger.info(`Report generated for analysis: ${analysisId}`);
      return report;
    } catch (error) {
      logger.error(`Report generation failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Generate verdict summary
   */
  static _generateVerdictSummary(assessment) {
    if (!assessment) {
      return 'Analysis not completed or inconclusive.';
    }

    const verdicts = {
      malicious: 'This file is classified as MALICIOUS based on multiple indicators of compromise, behavioral evidence, and threat intelligence.',
      suspicious: 'This file is classified as SUSPICIOUS with multiple indicators suggesting potential malicious intent. Further investigation recommended.',
      benign: 'This file is classified as BENIGN with no significant indicators of malicious behavior detected.',
      inconclusive: 'Analysis results are INCONCLUSIVE. While some indicators were detected, they do not conclusively indicate malicious intent.',
    };

    const verdict = verdicts[assessment.verdict] || 'Analysis results are inconclusive.';
    
    return `${verdict} Risk level: ${assessment.level.toUpperCase()} (${assessment.score}/100).`;
  }

  /**
   * Generate recommendations
   */
  static _generateRecommendations(assessment, staticResults, dynamicResults) {
    const recommendations = [];

    if (!assessment) {
      recommendations.push('Run a full analysis to determine the nature of this sample.');
      return recommendations;
    }

    if (assessment.verdict === 'malicious') {
      recommendations.push('IMMEDIATE ACTION: Block all associated IOCs across your environment.');
      recommendations.push('Alert security team and initiate incident response procedures.');
      recommendations.push('Isolate any systems that may have been exposed to this sample.');

      if (staticResults) {
        const yaraMatches = staticResults.yaraMatches || [];
        if (yaraMatches.length > 0) {
          recommendations.push(`Review and update YARA rules based on findings: ${yaraMatches.map(m => m.ruleName).join(', ')}`);
        }
      }

      if (dynamicResults) {
        const networkEvents = dynamicResults.networkEvents || [];
        const externalConnections = networkEvents.filter(e =>
          e.destinationIp && !e.destinationIp.startsWith('192.168.') &&
          !e.destinationIp.startsWith('10.') && !e.destinationIp.startsWith('172.16.')
        );
        if (externalConnections.length > 0) {
          recommendations.push('Block external network connections to the observed IPs and domains.');
        }

        const persistence = dynamicResults.persistence || [];
        if (persistence.length > 0) {
          recommendations.push('Check systems for persistence mechanisms and remove them.');
        }
      }

    } else if (assessment.verdict === 'suspicious') {
      recommendations.push('Monitor for related activity across the environment.');
      recommendations.push('Quarantine the sample until further analysis can be performed.');
      recommendations.push('Consider performing additional behavioral analysis.');

    } else if (assessment.verdict === 'inconclusive') {
      recommendations.push('Submit sample for additional analysis or manual review.');
      recommendations.push('Consider running in a more comprehensive sandbox environment.');
      recommendations.push('Review the sample\'s behavior in a different environment configuration.');
    } else {
      // Benign or unknown
      recommendations.push('No immediate action required, but continue monitoring for similar files.');
      recommendations.push('Update baseline detection for this file type to reduce future false positives.');
    }

    return recommendations;
  }

  /**
   * Generate summary for dashboard
   */
  static async generateSummary(analysisId) {
    try {
      const report = await this.generateReport(analysisId);
      
      return {
        sample: {
          filename: report.sampleInfo.filename,
          sha256: report.sampleInfo.sha256,
          fileType: report.sampleInfo.fileType,
        },
        verdict: report.finalVerdict,
        summary: {
          yaraMatches: report.summary.statistics.yaraMatches,
          totalIOCs: report.summary.statistics.totalIOCs,
          behavioralFindings: report.summary.statistics.behavioralFindings,
          staticFindings: report.summary.statistics.staticFindings,
        },
        iocs: {
          total: report.iocs.total,
          highSeverity: report.iocs.items.filter(i => i.severity === 'high' || i.severity === 'critical').length,
        },
        recommendations: report.summary.recommendations.slice(0, 5),
        timestamp: report.metadata.reportGeneratedAt,
      };
    } catch (error) {
      logger.error(`Failed to generate report summary: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Export report as JSON
   */
  static async exportJSON(analysisId) {
    try {
      const report = await this.generateReport(analysisId);
      return report;
    } catch (error) {
      logger.error(`Failed to export JSON report: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Check if report exists
   */
  static async hasReport(analysisId) {
    try {
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      return analysis && analysis.status === 'completed' && analysis.threatAssessment;
    } catch (error) {
      return false;
    }
  }
}

module.exports = ReportService;