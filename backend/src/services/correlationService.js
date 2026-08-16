const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class CorrelationService {
  /**
   * Correlate findings from multiple sources
   */
  static async correlate(analysisData) {
    try {
      const {
        staticAnalysis,
        dynamicAnalysis,
        virusTotalReport,
        iocs,
        behaviors,
      } = analysisData;

      const correlated = {
        findings: [],
        confidence: 0,
        evidenceMap: {},
        summary: '',
      };

      // 1. Correlate static and dynamic findings
      const staticFindings = staticAnalysis?.findings || [];
      const dynamicBehaviors = dynamicAnalysis?.behaviors || [];

      for (const staticFinding of staticFindings) {
        // Look for matching dynamic behavior
        const matchingDynamic = dynamicBehaviors.find(b => 
          b.type === staticFinding.type || 
          b.description.toLowerCase().includes(staticFinding.type?.toLowerCase() || '')
        );

        if (matchingDynamic) {
          correlated.findings.push({
            type: staticFinding.type,
            description: `Static finding "${staticFinding.description}" correlated with dynamic behavior "${matchingDynamic.description}"`,
            sources: ['static', 'dynamic'],
            confidence: Math.min(staticFinding.confidence || 0.5, matchingDynamic.confidence || 0.5) + 0.2,
            severity: this._calculateSeverity(staticFinding.severity, matchingDynamic.severity),
            evidence: {
              static: staticFinding,
              dynamic: matchingDynamic,
            },
          });
        } else {
          // Standalone static finding
          correlated.findings.push({
            type: staticFinding.type,
            description: staticFinding.description,
            sources: ['static'],
            confidence: staticFinding.confidence || 0.3,
            severity: staticFinding.severity || 'low',
            evidence: {
              static: staticFinding,
            },
          });
        }
      }

      // 2. Add standalone dynamic behaviors
      for (const behavior of dynamicBehaviors) {
        const alreadyCorrelated = correlated.findings.some(f => 
          f.evidence.dynamic && f.evidence.dynamic._id === behavior._id
        );

        if (!alreadyCorrelated) {
          correlated.findings.push({
            type: behavior.type,
            description: behavior.description,
            sources: ['dynamic'],
            confidence: behavior.confidence || 0.5,
            severity: behavior.severity || 'medium',
            evidence: {
              dynamic: behavior,
            },
          });
        }
      }

      // 3. Add IOC correlations
      const iocFindings = await this._correlateIOCs(iocs, correlated.findings);
      correlated.findings.push(...iocFindings);

      // 4. Add VirusTotal correlations
      if (virusTotalReport && virusTotalReport.isMalicious()) {
        correlated.findings.push({
          type: 'virustotal_detection',
          description: `VirusTotal detected as malicious by ${virusTotalReport.stats.malicious} engines`,
          sources: ['virustotal'],
          confidence: 0.9,
          severity: 'high',
          evidence: {
            virustotal: virusTotalReport,
          },
        });
      }

      // 5. Calculate overall confidence
      correlated.confidence = this._calculateOverallConfidence(correlated.findings);

      // 6. Generate summary
      correlated.summary = this._generateSummary(correlated.findings);

      // 7. Build evidence map for traceability
      correlated.evidenceMap = this._buildEvidenceMap(correlated.findings);

      logger.info(`Correlation complete: ${correlated.findings.length} findings`);
      return correlated;
    } catch (error) {
      logger.error(`Correlation failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Correlate IOCs with findings
   */
  static async _correlateIOCs(iocs, existingFindings) {
    const findings = [];

    if (!iocs || iocs.length === 0) {
      return findings;
    }

    // Group IOCs by type and severity
    const iocGroups = {};
    for (const ioc of iocs) {
      if (!iocGroups[ioc.type]) {
        iocGroups[ioc.type] = [];
      }
      iocGroups[ioc.type].push(ioc);
    }

    // Check for high-confidence IOCs
    for (const [type, group] of Object.entries(iocGroups)) {
      const highConfidence = group.filter(i => i.confidence > 0.7);
      if (highConfidence.length > 0) {
        const maxSeverity = highConfidence.reduce((max, i) => 
          this._severityRank(i.severity) > this._severityRank(max.severity) ? i : max
        );

        findings.push({
          type: `ioc_${type}`,
          description: `Found ${highConfidence.length} high-confidence IOC${highConfidence.length > 1 ? 's' : ''} of type ${type}`,
          sources: ['ioc'],
          confidence: Math.min(highConfidence.reduce((sum, i) => sum + i.confidence, 0) / highConfidence.length, 1.0),
          severity: maxSeverity.severity || 'medium',
          evidence: {
            iocs: highConfidence,
          },
        });
      }
    }

    return findings;
  }

  /**
   * Calculate severity from multiple sources
   */
  static _calculateSeverity(severity1, severity2) {
    const rank = {
      low: 0,
      medium: 1,
      high: 2,
      critical: 3,
    };
    
    const ranks = [severity1, severity2]
      .filter(s => s)
      .map(s => rank[s.toLowerCase()] || 0);
    
    if (ranks.length === 0) return 'low';
    
    const maxRank = Math.max(...ranks);
    for (const [key, value] of Object.entries(rank)) {
      if (value === maxRank) return key;
    }
    return 'medium';
  }

  /**
   * Get severity rank
   */
  static _severityRank(severity) {
    const ranks = { low: 0, medium: 1, high: 2, critical: 3 };
    return ranks[severity?.toLowerCase()] || 0;
  }

  /**
   * Calculate overall confidence
   */
  static _calculateOverallConfidence(findings) {
    if (findings.length === 0) return 0;

    // Weighted average based on confidence and severity
    const weights = {
      low: 0.5,
      medium: 1.0,
      high: 1.5,
      critical: 2.0,
    };

    let totalWeight = 0;
    let weightedConfidence = 0;

    for (const finding of findings) {
      const weight = weights[finding.severity?.toLowerCase()] || 1.0;
      const confidence = finding.confidence || 0.5;
      
      totalWeight += weight;
      weightedConfidence += confidence * weight;
    }

    // Add bonus for multiple correlated sources
    const multiSourceFindings = findings.filter(f => f.sources && f.sources.length > 1);
    const bonus = Math.min(multiSourceFindings.length * 0.05, 0.2);

    const baseConfidence = totalWeight > 0 ? weightedConfidence / totalWeight : 0;
    return Math.min(baseConfidence + bonus, 1.0);
  }

  /**
   * Generate summary
   */
  static _generateSummary(findings) {
    if (findings.length === 0) {
      return 'No correlated findings.';
    }

    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;
    const mediumCount = findings.filter(f => f.severity === 'medium').length;
    const lowCount = findings.filter(f => f.severity === 'low').length;

    const parts = [];
    if (criticalCount > 0) parts.push(`${criticalCount} critical findings`);
    if (highCount > 0) parts.push(`${highCount} high findings`);
    if (mediumCount > 0) parts.push(`${mediumCount} medium findings`);
    if (lowCount > 0) parts.push(`${lowCount} low findings`);

    let summary = `Analysis correlated ${findings.length} findings: ${parts.join(', ')}.`;

    // Add dominant findings
    const criticalFindings = findings.filter(f => f.severity === 'critical');
    if (criticalFindings.length > 0) {
      const descriptions = criticalFindings.slice(0, 3).map(f => f.description);
      summary += ` Critical findings include: ${descriptions.join('; ')}.`;
    }

    return summary;
  }

  /**
   * Build evidence map for traceability
   */
  static _buildEvidenceMap(findings) {
    const map = {};

    for (const finding of findings) {
      const key = `${finding.type}-${finding.description.substring(0, 30)}`;
      map[key] = {
        description: finding.description,
        sources: finding.sources || [],
        severity: finding.severity,
        confidence: finding.confidence,
        evidence: finding.evidence,
      };
    }

    return map;
  }

  /**
   * Get correlation summary for sample
   */
  static async getCorrelationSummary(correlatedData) {
    if (!correlatedData || !correlatedData.findings) {
      return null;
    }

    const findings = correlatedData.findings;
    const highSeverity = findings.filter(f => 
      f.severity === 'high' || f.severity === 'critical'
    );

    return {
      totalFindings: findings.length,
      highSeverityCount: highSeverity.length,
      confidence: correlatedData.confidence || 0,
      summary: correlatedData.summary || '',
      topFindings: highSeverity.slice(0, 5).map(f => ({
        type: f.type,
        description: f.description,
        severity: f.severity,
        confidence: f.confidence,
      })),
      evidenceMap: correlatedData.evidenceMap || {},
    };
  }
}

module.exports = CorrelationService;