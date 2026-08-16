const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class RiskService {
  /**
   * Calculate risk assessment
   */
  static async calculateRisk(analysisData) {
    try {
      const {
        sample,
        staticAnalysis,
        dynamicAnalysis,
        virusTotalReport,
        iocs,
        behaviors,
        correlatedFindings,
      } = analysisData;

      let score = 0;
      const contributors = [];
      const factors = [];

      // 1. Static analysis contribution (max 25 points)
      if (staticAnalysis) {
        const staticScore = this._calculateStaticRisk(staticAnalysis);
        score += staticScore;
        contributors.push({
          source: 'static_analysis',
          score: staticScore,
          level: this._scoreToLevel(staticScore),
          factors: this._getStaticFactors(staticAnalysis),
        });
        factors.push(...this._getStaticFactors(staticAnalysis));
      }

      // 2. Dynamic analysis contribution (max 30 points)
      if (dynamicAnalysis) {
        const dynamicScore = this._calculateDynamicRisk(dynamicAnalysis);
        score += dynamicScore;
        contributors.push({
          source: 'dynamic_analysis',
          score: dynamicScore,
          level: this._scoreToLevel(dynamicScore),
          factors: this._getDynamicFactors(dynamicAnalysis),
        });
        factors.push(...this._getDynamicFactors(dynamicAnalysis));
      }

      // 3. VirusTotal contribution (max 20 points)
      if (virusTotalReport) {
        const vtScore = this._calculateVTRisk(virusTotalReport);
        score += vtScore;
        contributors.push({
          source: 'virustotal',
          score: vtScore,
          level: this._scoreToLevel(vtScore),
          factors: this._getVTFactors(virusTotalReport),
        });
        factors.push(...this._getVTFactors(virusTotalReport));
      }

      // 4. IOC contribution (max 15 points)
      if (iocs && iocs.length > 0) {
        const iocScore = this._calculateIOCRisk(iocs);
        score += iocScore;
        contributors.push({
          source: 'iocs',
          score: iocScore,
          level: this._scoreToLevel(iocScore),
          factors: this._getIOCFactors(iocs),
        });
        factors.push(...this._getIOCFactors(iocs));
      }

      // 5. Behavior contribution (max 10 points)
      if (behaviors && behaviors.length > 0) {
        const behaviorScore = this._calculateBehaviorRisk(behaviors);
        score += behaviorScore;
        contributors.push({
          source: 'behaviors',
          score: behaviorScore,
          level: this._scoreToLevel(behaviorScore),
          factors: this._getBehaviorFactors(behaviors),
        });
        factors.push(...this._getBehaviorFactors(behaviors));
      }

      // Normalize score to 0-100
      score = Math.min(score, 100);

      // Determine level
      const level = this._scoreToLevel(score);

      // Determine verdict
      const verdict = this._determineVerdict(score, level, factors);

      // Generate explanation
      const explanation = this._generateExplanation(score, level, verdict, contributors, factors);

      // Build assessment
      const assessment = {
        score,
        level,
        verdict,
        confidence: this._calculateConfidence(contributors),
        contributors,
        factors,
        explanation,
        keyFindings: this._extractKeyFindings(factors, score),
        timestamp: new Date(),
      };

      logger.info(`Risk assessment calculated: ${level} (${score}/100)`);
      return assessment;
    } catch (error) {
      logger.error(`Risk calculation failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Calculate risk from static analysis
   */
  static _calculateStaticRisk(staticAnalysis) {
    let score = 0;

    if (!staticAnalysis) return 0;

    // YARA matches (5 points each, max 10)
    const yaraMatches = staticAnalysis.yaraMatches || [];
    if (yaraMatches.length > 0) {
      const yaraScore = Math.min(yaraMatches.length * 5, 10);
      score += yaraScore;
    }

    // Suspicious imports (1 point each, max 5)
    const imports = staticAnalysis.imports || [];
    const suspiciousAPIs = [
      'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 
      'CreateProcess', 'WinExec', 'ShellExecute', 'RegSetValueEx',
      'CreateService', 'StartService', 'InternetOpen', 'URLDownloadToFile',
      'GetAsyncKeyState', 'SetWindowsHookEx'
    ];
    const suspiciousCount = this._countSuspiciousImports(imports, suspiciousAPIs);
    score += Math.min(suspiciousCount, 5);

    // Suspicious strings (1 point per 5, max 5)
    const strings = staticAnalysis.strings || {};
    const suspiciousStrings = strings.suspicious || [];
    score += Math.min(Math.floor(suspiciousStrings.length / 5), 5);

    // High entropy sections (2 points each, max 4)
    const entropy = staticAnalysis.entropy || {};
    const highEntropy = entropy.highEntropySections || [];
    score += Math.min(highEntropy.length * 2, 4);

    // Findings from static analysis (weighted)
    const findings = staticAnalysis.findings || [];
    for (const finding of findings) {
      if (finding.severity === 'critical') score += 3;
      else if (finding.severity === 'high') score += 2;
      else if (finding.severity === 'medium') score += 1;
    }

    return Math.min(score, 25);
  }

  /**
   * Calculate risk from dynamic analysis
   */
  static _calculateDynamicRisk(dynamicAnalysis) {
    let score = 0;

    if (!dynamicAnalysis) return 0;

    // Process activity
    const processes = dynamicAnalysis.processes || [];
    const suspiciousProcesses = processes.filter(p => 
      p.name && (
        p.name.toLowerCase().includes('cmd') ||
        p.name.toLowerCase().includes('powershell') ||
        p.name.toLowerCase().includes('wscript') ||
        p.name.toLowerCase().includes('cscript') ||
        p.name.toLowerCase().includes('rundll32') ||
        p.name.toLowerCase().includes('regsvr32')
      )
    );
    score += Math.min(suspiciousProcesses.length * 3, 6);

    // File activity
    const fileEvents = dynamicAnalysis.fileEvents || [];
    const suspiciousFileEvents = fileEvents.filter(e =>
      e.operation === 'create' || e.operation === 'modify'
    );
    score += Math.min(Math.floor(suspiciousFileEvents.length / 5) * 2, 6);

    // Registry modifications
    const registryEvents = dynamicAnalysis.registryEvents || [];
    const suspiciousRegistry = registryEvents.filter(e =>
      e.operation === 'create' || e.operation === 'modify'
    );
    score += Math.min(Math.floor(suspiciousRegistry.length / 3) * 2, 6);

    // Network activity
    const networkEvents = dynamicAnalysis.networkEvents || [];
    const externalConnections = networkEvents.filter(e =>
      e.destinationIp && !e.destinationIp.startsWith('192.168.') &&
      !e.destinationIp.startsWith('10.') && !e.destinationIp.startsWith('172.16.') &&
      !e.destinationIp.startsWith('127.0.0.1') && e.destinationIp !== '0.0.0.0'
    );
    score += Math.min(externalConnections.length * 3, 6);

    // Persistence mechanisms
    const persistence = dynamicAnalysis.persistence || [];
    score += Math.min(persistence.length * 3, 6);

    // Behaviors
    const behaviors = dynamicAnalysis.behaviors || [];
    for (const behavior of behaviors) {
      if (behavior.severity === 'critical') score += 4;
      else if (behavior.severity === 'high') score += 3;
      else if (behavior.severity === 'medium') score += 2;
    }

    return Math.min(score, 30);
  }

  /**
   * Calculate risk from VirusTotal
   */
  static _calculateVTRisk(vtReport) {
    let score = 0;

    if (!vtReport) return 0;

    const stats = vtReport.stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = stats.total || 0;

    if (total > 0) {
      // Detection ratio
      const ratio = malicious / total;
      if (ratio >= 0.8) score += 15;
      else if (ratio >= 0.5) score += 10;
      else if (ratio >= 0.3) score += 5;
      else if (ratio >= 0.1) score += 2;

      // Suspicious detections
      if (suspicious > 0) {
        score += Math.min(suspicious, 5);
      }
    }

    // Threat intelligence
    if (vtReport.threatIntelligence) {
      const threatNames = vtReport.threatIntelligence.threatNames || [];
      if (threatNames.length > 0) score += 5;

      const families = vtReport.threatIntelligence.families || [];
      if (families.length > 0) score += 5;
    }

    return Math.min(score, 20);
  }

  /**
   * Calculate risk from IOCs
   */
  static _calculateIOCRisk(iocs) {
    let score = 0;

    if (!iocs || iocs.length === 0) return 0;

    // High severity IOCs
    const highSeverity = iocs.filter(i => i.severity === 'critical' || i.severity === 'high');
    score += Math.min(highSeverity.length * 3, 10);

    // Medium severity IOCs
    const mediumSeverity = iocs.filter(i => i.severity === 'medium');
    score += Math.min(mediumSeverity.length * 1, 5);

    // High confidence IOCs
    const highConfidence = iocs.filter(i => i.confidence > 0.8);
    score += Math.min(highConfidence.length * 2, 5);

    // Network-related IOCs
    const networkIOCs = iocs.filter(i => 
      i.type === 'ip' || i.type === 'domain' || i.type === 'url'
    );
    score += Math.min(networkIOCs.length * 2, 5);

    return Math.min(score, 15);
  }

  /**
   * Calculate risk from behaviors
   */
  static _calculateBehaviorRisk(behaviors) {
    let score = 0;

    if (!behaviors || behaviors.length === 0) return 0;

    // Critical behaviors
    const critical = behaviors.filter(b => b.severity === 'critical');
    score += Math.min(critical.length * 5, 10);

    // High behaviors
    const high = behaviors.filter(b => b.severity === 'high');
    score += Math.min(high.length * 2, 5);

    // Medium behaviors
    const medium = behaviors.filter(b => b.severity === 'medium');
    score += Math.min(medium.length * 1, 3);

    return Math.min(score, 10);
  }

  /**
   * Count suspicious imports
   */
  static _countSuspiciousImports(imports, suspiciousAPIs) {
    let count = 0;
    for (const imp of imports) {
      if (imp.functions) {
        for (const func of imp.functions) {
          if (suspiciousAPIs.includes(func)) {
            count++;
          }
        }
      }
    }
    return count;
  }

  /**
   * Convert score to level
   */
  static _scoreToLevel(score) {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  }

  /**
   * Get static analysis factors
   */
  static _getStaticFactors(staticAnalysis) {
    const factors = [];

    if (!staticAnalysis) return factors;

    const yaraMatches = staticAnalysis.yaraMatches || [];
    if (yaraMatches.length > 0) {
      factors.push(`YARA matches: ${yaraMatches.map(m => m.ruleName).join(', ')}`);
    }

    const findings = staticAnalysis.findings || [];
    for (const finding of findings) {
      factors.push(`Static finding: ${finding.description} (${finding.severity})`);
    }

    return factors;
  }

  /**
   * Get dynamic analysis factors
   */
  static _getDynamicFactors(dynamicAnalysis) {
    const factors = [];

    if (!dynamicAnalysis) return factors;

    const processes = dynamicAnalysis.processes || [];
    const suspiciousProcesses = processes.filter(p => 
      p.name && (
        p.name.toLowerCase().includes('cmd') ||
        p.name.toLowerCase().includes('powershell') ||
        p.name.toLowerCase().includes('wscript') ||
        p.name.toLowerCase().includes('cscript')
      )
    );
    if (suspiciousProcesses.length > 0) {
      factors.push(`Suspicious process execution: ${suspiciousProcesses.map(p => p.name).join(', ')}`);
    }

    const persistence = dynamicAnalysis.persistence || [];
    if (persistence.length > 0) {
      factors.push(`Persistence mechanisms: ${persistence.length} found`);
    }

    const networkEvents = dynamicAnalysis.networkEvents || [];
    const externalConnections = networkEvents.filter(e =>
      e.destinationIp && !e.destinationIp.startsWith('192.168.') &&
      !e.destinationIp.startsWith('10.') && !e.destinationIp.startsWith('172.16.')
    );
    if (externalConnections.length > 0) {
      factors.push(`Network connections: ${externalConnections.length} external connections`);
    }

    const behaviors = dynamicAnalysis.behaviors || [];
    for (const behavior of behaviors) {
      factors.push(`Behavior: ${behavior.description} (${behavior.severity})`);
    }

    return factors;
  }

  /**
   * Get VirusTotal factors
   */
  static _getVTFactors(vtReport) {
    const factors = [];

    if (!vtReport) return factors;

    const stats = vtReport.stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = stats.total || 0;

    if (malicious > 0) {
      factors.push(`VirusTotal: ${malicious}/${total} detections`);
    }

    if (suspicious > 0) {
      factors.push(`VirusTotal: ${suspicious} suspicious detections`);
    }

    if (vtReport.threatIntelligence) {
      const families = vtReport.threatIntelligence.families || [];
      if (families.length > 0) {
        factors.push(`Malware family: ${families.join(', ')}`);
      }
    }

    return factors;
  }

  /**
   * Get IOC factors
   */
  static _getIOCFactors(iocs) {
    const factors = [];

    if (!iocs || iocs.length === 0) return factors;

    const highSeverity = iocs.filter(i => i.severity === 'critical' || i.severity === 'high');
    if (highSeverity.length > 0) {
      factors.push(`High-severity IOCs: ${highSeverity.length}`);
    }

    const networkIOCs = iocs.filter(i => i.type === 'ip' || i.type === 'domain');
    if (networkIOCs.length > 0) {
      factors.push(`Network IOCs: ${networkIOCs.map(i => i.value).join(', ')}`);
    }

    return factors;
  }

  /**
   * Get behavior factors
   */
  static _getBehaviorFactors(behaviors) {
    const factors = [];

    if (!behaviors || behaviors.length === 0) return factors;

    const critical = behaviors.filter(b => b.severity === 'critical');
    if (critical.length > 0) {
      factors.push(`Critical behaviors: ${critical.map(b => b.type).join(', ')}`);
    }

    const high = behaviors.filter(b => b.severity === 'high');
    if (high.length > 0) {
      factors.push(`High-risk behaviors: ${high.map(b => b.type).join(', ')}`);
    }

    return factors;
  }

  /**
   * Determine final verdict
   */
  static _determineVerdict(score, level, factors) {
    // If there are critical findings, mark as malicious
    const hasCriticalFactors = factors.some(f => 
      f.toLowerCase().includes('critical') ||
      f.toLowerCase().includes('ransomware') ||
      f.toLowerCase().includes('injection') ||
      f.toLowerCase().includes('persistence')
    );

    if (level === 'critical' || (level === 'high' && hasCriticalFactors)) {
      return 'malicious';
    }

    if (level === 'high') {
      return 'suspicious';
    }

    if (level === 'medium') {
      // Check if there are suspicious indicators
      const hasSuspiciousIndicators = factors.some(f =>
        f.toLowerCase().includes('suspicious') ||
        f.toLowerCase().includes('unusual') ||
        f.toLowerCase().includes('detection')
      );
      return hasSuspiciousIndicators ? 'suspicious' : 'inconclusive';
    }

    if (score > 0 && level === 'low') {
      return 'inconclusive';
    }

    return 'benign';
  }

  /**
   * Calculate confidence
   */
  static _calculateConfidence(contributors) {
    let totalScore = 0;
    let totalWeight = 0;

    for (const contributor of contributors) {
      const weight = contributor.score > 0 ? 1 : 0.3;
      totalScore += contributor.score * weight;
      totalWeight += weight;
    }

    if (totalWeight === 0) return 0;

    const confidence = Math.min(totalScore / (totalWeight * 100) * 0.8 + 0.2, 1.0);
    return Math.round(confidence * 100) / 100;
  }

  /**
   * Generate explanation
   */
  static _generateExplanation(score, level, verdict, contributors, factors) {
    const summary = `Risk assessment: ${level.toUpperCase()} (${score}/100). Verdict: ${verdict.toUpperCase()}.`;

    let detailed = `Contributing factors:\n`;
    for (const contributor of contributors) {
      if (contributor.score > 0) {
        detailed += `- ${contributor.source}: ${contributor.score} points (${contributor.level})\n`;
        if (contributor.factors && contributor.factors.length > 0) {
          for (const factor of contributor.factors.slice(0, 3)) {
            detailed += `  - ${factor}\n`;
          }
        }
      }
    }

    if (factors.length === 0) {
      detailed += '- No significant risk factors identified.\n';
    }

    return {
      summary,
      detailed: detailed,
    };
  }

  /**
   * Extract key findings
   */
  static _extractKeyFindings(factors, score) {
    const findings = [];

    // Find critical factors
    const criticalFactors = factors.filter(f =>
      f.toLowerCase().includes('critical') ||
      f.toLowerCase().includes('ransomware') ||
      f.toLowerCase().includes('injection')
    );

    for (const factor of criticalFactors.slice(0, 5)) {
      findings.push({
        type: 'critical_finding',
        description: factor,
        severity: 'critical',
        evidence: factor,
      });
    }

    // Find high factors
    if (findings.length < 5) {
      const highFactors = factors.filter(f =>
        f.toLowerCase().includes('high') ||
        f.toLowerCase().includes('malicious') ||
        f.toLowerCase().includes('detection')
      );
      for (const factor of highFactors.slice(0, 5 - findings.length)) {
        findings.push({
          type: 'high_finding',
          description: factor,
          severity: 'high',
          evidence: factor,
        });
      }
    }

    if (findings.length === 0 && score > 0) {
      findings.push({
        type: 'general_risk',
        description: `Risk score: ${score}/100 - ${this._scoreToLevel(score).toUpperCase()}`,
        severity: this._scoreToLevel(score),
        evidence: 'Combined analysis',
      });
    }

    return findings;
  }

  /**
   * Get risk summary
   */
  static getRiskSummary(assessment) {
    if (!assessment) return null;

    return {
      score: assessment.score,
      level: assessment.level,
      verdict: assessment.verdict,
      confidence: assessment.confidence,
      keyFindings: assessment.keyFindings ? assessment.keyFindings.length : 0,
      timestamp: assessment.timestamp,
    };
  }

  /**
   * Validate risk assessment
   */
  static validateAssessment(assessment) {
    const errors = [];

    if (!assessment) {
      errors.push('Assessment is null');
      return errors;
    }

    if (typeof assessment.score !== 'number' || assessment.score < 0 || assessment.score > 100) {
      errors.push('Invalid score');
    }

    if (!['low', 'medium', 'high', 'critical'].includes(assessment.level)) {
      errors.push('Invalid level');
    }

    if (!['malicious', 'suspicious', 'benign', 'inconclusive', 'not_analyzed'].includes(assessment.verdict)) {
      errors.push('Invalid verdict');
    }

    if (typeof assessment.confidence !== 'number' || assessment.confidence < 0 || assessment.confidence > 1) {
      errors.push('Invalid confidence');
    }

    return errors;
  }
}

module.exports = RiskService;