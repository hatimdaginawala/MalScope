const StaticAnalysis = require('../models/StaticAnalysis');
const MalwareSample = require('../models/MalwareSample');
const { Analysis } = require('../models/Analysis');
const AnalysisService = require('./analysisService');
const PythonAnalysisService = require('./pythonAnalysisService');
const IOCService = require('./iocService');
const IOC = require('../models/IOC');
const ConfigurationService = require('./configurationService');
const SimilarityService = require('./similarityService');
const FamilyIntelligenceService = require('./familyIntelligenceService');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class StaticAnalysisService {
  static async analyze(analysisId) {
    try {
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      const canProceed = await AnalysisService.canProceed(analysisId);
      if (!canProceed) {
        throw new ApiError(400, `Analysis cannot proceed in current state: ${analysis.status}`);
      }

      await AnalysisService.updateStatus(analysisId, 'static_analysis', 'Starting static analysis');

      const sample = await MalwareSample.findById(analysis.sample);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      let pythonResult;
      try {
        pythonResult = await PythonAnalysisService.runStaticAnalysis(sample.storagePath);
      } catch (error) {
        await AnalysisService.setError(analysisId, `Python analysis failed: ${error.message}`, 'static_analysis');
        throw error;
      }

      if (!pythonResult.success) {
        const errorMsg = pythonResult.errors ? pythonResult.errors.join(', ') : 'Unknown Python error';
        await AnalysisService.setError(analysisId, errorMsg, 'static_analysis');
        throw new ApiError(500, `Static analysis failed: ${errorMsg}`);
      }

      const result = pythonResult.result || {};

      // ===== Log API Intelligence =====
      logger.info(`API Intelligence from Python: total_apis=${result.apiIntelligence?.total_apis || 0}, highRiskApis=${result.highRiskApis?.length || 0}`);
      
      // ===== Log String Intelligence =====
      logger.info(`String Intelligence from Python: total_strings=${result.stringIntelligence?.total_strings || 0}, classified=${result.stringIntelligence?.classified_count || 0}`);

      // ===== API Intelligence with proper fallback =====
      const apiIntelligence = result.apiIntelligence || {
        total_apis: 0,
        total_categories: 0,
        categories: {},
        severity_summary: { low: 0, medium: 0, high: 0, critical: 0 },
        top_categories: [],
        capabilities: [],
      };

      const highRiskApis = result.highRiskApis || [];

      // ===== NEW: String Intelligence with proper fallback =====
      const stringIntelligence = result.stringIntelligence || {
        total_strings: 0,
        classified_count: 0,
        category_counts: {},
        suspicious_count: 0,
        ioc_candidates: 0,
        severity_summary: { low: 0, medium: 0, high: 0, critical: 0 },
        top_categories: [],
      };

      // ===== Create StaticAnalysis record =====
      const staticAnalysis = new StaticAnalysis({
        sample: sample._id,
        analysis: analysisId,
        fileInfo: result.file || {},
        dosHeader: result.dosHeader || null,
        coffHeader: result.coffHeader || null,
        optionalHeader: result.optionalHeader || null,
        dataDirectories: result.dataDirectories || [],
        sections: result.sections || [],
        imports: result.imports || [],
        exports: result.exports || [],
        strings: result.strings || { ascii: [], unicode: [], suspicious: [] },
        entropy: result.entropy || { overall: 0, sections: [], highEntropySections: [] },
        resources: result.resources || [],
        tls: result.tls || null,
        debugInfo: result.debugInfo || null,
        richHeader: result.richHeader || null,
        signature: result.signature || { signed: false },
        
        // ===== API Intelligence =====
        apiIntelligence: apiIntelligence,
        highRiskApis: highRiskApis,
        
        // ===== NEW: String Intelligence =====
        stringIntelligence: stringIntelligence,
        
        yaraMatches: result.yaraMatches || [],
        findings: result.findings || [],
        processedAt: new Date(),
        processingDuration: pythonResult.duration || 0,
        warnings: pythonResult.warnings || [],
        errors: pythonResult.errors || [],
        version: '2.0.0',
        rawResult: result,
        // In the StaticAnalysis creation, add:
resourceDetails: result.resourceDetails || [],
resourceSummary: result.resourceSummary || {
  total_resources: 0,
  suspicious_resources: 0,
  total_size: 0,
  categories: {},
  types: {},
  has_suspicious: false,
},
signatureAnalysis: result.signatureAnalysis || {
  is_signed: false,
  verification_status: 'Not verified',
  certificate_chain: [],
  certificate_count: 0,
  is_timestamped: false,
  is_trusted: false,
  is_expired: false,
  is_revoked: false,
  warnings: [],
},
      });

      await staticAnalysis.save();

      // ===== Extract and save IOCs =====
      const pythonIOCs = result.iocs || [];
      logger.info(`Found ${pythonIOCs.length} IOCs from Python analysis`);
      
      let savedIOCCount = 0;
      const iocIds = [];
      for (const iocData of pythonIOCs) {
        try {
          const type = iocData.type || 'other';
          const value = iocData.value || '';
          
          if (!value) continue;
          
          const normalizedValue = value.toLowerCase().trim();
          
          const existing = await IOC.findOne({
            sample: sample._id,
            type: type,
            normalizedValue: normalizedValue,
          });
          
          let ioc;
          if (!existing) {
            const newIOC = new IOC({
              type: type,
              value: value,
              normalizedValue: normalizedValue,
              source: 'static_analysis',
              sample: sample._id,
              analysis: analysisId,
              confidence: iocData.confidence || 0.5,
              severity: 'medium',
              context: iocData.context || {},
              tags: [],
              firstSeen: new Date(),
              lastSeen: new Date(),
            });
            ioc = await newIOC.save();
          } else {
            existing.lastSeen = new Date();
            existing.confidence = Math.max(existing.confidence, iocData.confidence || 0.5);
            ioc = await existing.save();
          }
          iocIds.push(ioc._id);
          savedIOCCount++;
        } catch (iocError) {
          logger.warn(`Failed to save IOC: ${iocError.message}`);
        }
      }
      logger.info(`Saved ${savedIOCCount} IOCs for sample ${sample._id}`);

      // ===== Update analysis with references =====
      await Analysis.updateOne(
        { _id: analysisId },
        {
          staticAnalysis: staticAnalysis._id,
          iocs: iocIds,
        }
      );

      await AnalysisService.updateStatus(analysisId, 'completed', 'Static analysis completed successfully');
      await AnalysisService.addLog(analysisId, 'Static analysis completed successfully', 'info');

      // ===== Log completion summary =====
      logger.info(`Analysis ${analysisId} completed. API Intelligence: ${apiIntelligence.total_apis} APIs, ${highRiskApis.length} high-risk. String Intelligence: ${stringIntelligence.total_strings} strings, ${stringIntelligence.classified_count} classified.`);

      return {
        staticAnalysis,
        pythonResult,
        iocs: pythonIOCs,
        warnings: pythonResult.warnings || [],
        errors: pythonResult.errors || [],
      };
    } catch (error) {
      logger.error(`Static analysis failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Extract configuration indicators from static analysis results
   */
  static _extractConfigurationIndicators(result) {
    const indicators = [];
    const strings = result.strings || {};
    const allStrings = [...(strings.ascii || []), ...(strings.unicode || [])];

    // Domain pattern
    const domainPattern = /\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b/g;
    const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const urlPattern = /https?:\/\/[^\s<>"']+/g;
    const filePathPattern = /[A-Za-z]:\\[^\\\s<>"']+\\[^\\\s<>"']+/g;
    const registryPattern = /[A-Za-z_][A-Za-z0-9_]*\\[A-Za-z_][A-Za-z0-9_]*\\[A-Za-z_][A-Za-z0-9_]*/g;

    const seen = new Set();

    for (const str of allStrings) {
      // Extract domains (skip common Windows DLLs)
      const domains = str.match(domainPattern) || [];
      for (const domain of domains) {
        const key = `domain:${domain}`;
        if (!seen.has(key) && !domain.endsWith('.dll') && !domain.endsWith('.exe')) {
          seen.add(key);
          indicators.push({
            type: 'c2_domain',
            value: domain,
            confidence: 0.4,
            severity: 'medium',
            evidence: str,
            tags: ['domain', 'string_analysis'],
          });
        }
      }

      // Extract IPs
      const ips = str.match(ipPattern) || [];
      for (const ip of ips) {
        const key = `ip:${ip}`;
        if (!seen.has(key) && !ip.startsWith('192.168.') && !ip.startsWith('10.') && !ip.startsWith('172.')) {
          seen.add(key);
          indicators.push({
            type: 'c2_ip',
            value: ip,
            confidence: 0.5,
            severity: 'high',
            evidence: str,
            tags: ['ip', 'string_analysis'],
          });
        }
      }

      // Extract URLs
      const urls = str.match(urlPattern) || [];
      for (const url of urls) {
        const key = `url:${url}`;
        if (!seen.has(key)) {
          seen.add(key);
          indicators.push({
            type: 'c2_url',
            value: url,
            confidence: 0.5,
            severity: 'high',
            evidence: str,
            tags: ['url', 'string_analysis'],
          });
        }
      }

      // Extract file paths
      const filePaths = str.match(filePathPattern) || [];
      for (const path of filePaths) {
        const key = `file_path:${path}`;
        if (!seen.has(key)) {
          seen.add(key);
          indicators.push({
            type: 'file_path',
            value: path,
            confidence: 0.3,
            severity: 'low',
            evidence: str,
            tags: ['file_path', 'string_analysis'],
          });
        }
      }

      // Extract registry paths
      const registryPaths = str.match(registryPattern) || [];
      for (const regPath of registryPaths) {
        const key = `registry_path:${regPath}`;
        if (!seen.has(key)) {
          seen.add(key);
          indicators.push({
            type: 'registry_path',
            value: regPath,
            confidence: 0.4,
            severity: 'medium',
            evidence: str,
            tags: ['registry', 'string_analysis'],
          });
        }
      }

      // Check for mutex-like strings
      const mutexPatterns = [
        /Global\\[A-Za-z0-9_\-]+/,
        /Local\\[A-Za-z0-9_\-]+/,
        /[A-Za-z0-9_\-]{8}-[A-Za-z0-9_\-]{4}-[A-Za-z0-9_\-]{4}-[A-Za-z0-9_\-]{4}-[A-Za-z0-9_\-]{12}/,
        /_[A-Za-z0-9_\-]{10,}/,
      ];
      for (const pattern of mutexPatterns) {
        const matches = str.match(pattern) || [];
        for (const match of matches) {
          const key = `mutex:${match}`;
          if (!seen.has(key) && match.length > 8) {
            seen.add(key);
            indicators.push({
              type: 'mutex',
              value: match,
              confidence: 0.3,
              severity: 'low',
              evidence: str,
              tags: ['mutex', 'string_analysis'],
            });
          }
        }
      }
    }

    // Check YARA matches for config indicators
    const yaraMatches = result.yaraMatches || [];
    for (const match of yaraMatches) {
      if (match.meta && match.meta.config) {
        indicators.push({
          type: 'other',
          value: `YARA:${match.ruleName}`,
          confidence: 0.7,
          severity: 'high',
          evidence: `YARA rule ${match.ruleName} matched`,
          tags: ['yara', 'config'],
        });
      }
    }

    return indicators;
  }

  /**
   * Infer static behaviors from analysis results
   */
static _inferBehaviors(result) {
  const behaviors = [];
  const imports = result.imports || [];
  const strings = result.strings || {};
  const allStrings = [...(strings.ascii || []), ...(strings.unicode || [])];
  const findings = result.findings || [];

  // Define capability categories and their indicators with valid enum types
  const capabilityMap = {
    'network_communication': {
      type: 'network_communication',
      imports: ['WinHttpOpen', 'HttpOpenRequest', 'InternetOpen', 'URLDownloadToFile', 'InternetConnect'],
      strings: ['http://', 'https://', '.onion', '.tor', 'User-Agent'],
      yaraKeywords: ['network', 'web', 'http'],
      weight: 0.6,
    },
    'file_manipulation': {
      type: 'file_drop',
      imports: ['CreateFile', 'WriteFile', 'ReadFile', 'DeleteFile', 'CopyFile', 'MoveFile'],
      strings: ['\\Temp\\', '\\AppData\\', '\\.exe', '\\.dll'],
      yaraKeywords: ['file', 'write', 'delete'],
      weight: 0.5,
    },
    'process_manipulation': {
      type: 'process_injection',
      imports: ['CreateProcess', 'CreateRemoteThread', 'WriteProcessMemory', 'ReadProcessMemory', 'VirtualAllocEx'],
      strings: ['CreateProcess', 'WriteProcessMemory', 'VirtualAlloc'],
      yaraKeywords: ['process', 'thread', 'inject'],
      weight: 0.6,
    },
    'persistence': {
      type: 'persistence',
      imports: ['RegSetValueEx', 'CreateService', 'StartService', 'SchTasks'],
      strings: ['CurrentVersion\\Run', 'CurrentVersion\\RunOnce', 'Schedule', 'Service'],
      yaraKeywords: ['persistence', 'registry', 'service'],
      weight: 0.5,
    },
    'registry_manipulation': {
      type: 'registry_modification',
      imports: ['RegCreateKeyEx', 'RegSetValueEx', 'RegDeleteKey', 'RegQueryValueEx'],
      strings: ['SYSTEM\\CurrentControlSet', 'Software\\Microsoft\\Windows'],
      yaraKeywords: ['registry', 'regkey'],
      weight: 0.4,
    },
    'anti_analysis': {
      type: 'anti_debug',
      imports: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'],
      strings: ['vmware', 'virtualbox', 'sandbox', 'debugger'],
      yaraKeywords: ['anti', 'debug', 'sandbox'],
      weight: 0.5,
    },
    'command_execution': {
      type: 'command_execution',
      imports: ['CreateProcess', 'WinExec', 'ShellExecute', 'system'],
      strings: ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'],
      yaraKeywords: ['command', 'execute', 'shell'],
      weight: 0.5,
    },
    'data_theft': {
      type: 'collection',
      imports: ['FindFirstFile', 'FindNextFile', 'ReadFile', 'GetClipboardData', 'GetAsyncKeyState'],
      strings: ['steal', 'keylog', 'clipboard', 'screenshot'],
      yaraKeywords: ['steal', 'exfil', 'keylog'],
      weight: 0.4,
    },
    'privilege_escalation': {
      type: 'privilege_escalation',
      imports: ['LookupPrivilegeValue', 'AdjustTokenPrivileges', 'OpenProcessToken'],
      strings: ['SeDebugPrivilege', 'SeShutdownPrivilege', 'SeTakeOwnershipPrivilege'],
      yaraKeywords: ['privilege', 'token', 'escalate'],
      weight: 0.5,
    },
    'defense_evasion': {
      type: 'defense_evasion',
      imports: ['VirtualProtect', 'WriteProcessMemory', 'NtSetInformationProcess'],
      strings: ['hide', 'evade', 'bypass', 'disable'],
      yaraKeywords: ['evasion', 'obfuscate', 'hide'],
      weight: 0.5,
    },
    'ransomware': {
      type: 'ransomware_behavior',
      imports: ['CryptEncrypt', 'CryptDecrypt', 'RtlEncryptMemory'],
      strings: ['encrypt', 'ransom', 'decrypt', 'bitcoin', 'wallet'],
      yaraKeywords: ['ransomware', 'encrypt', 'ransom'],
      weight: 0.6,
    },
  };

  // Track matched capabilities
  const matchedCapabilities = {};

  // Check imports
  const importFuncs = new Set();
  for (const imp of imports) {
    for (const func of imp.functions || []) {
      importFuncs.add(func);
    }
  }

  for (const [key, data] of Object.entries(capabilityMap)) {
    let confidence = 0;
    const evidence = [];

    // Check imports
    for (const imp of data.imports) {
      if (importFuncs.has(imp)) {
        confidence += 0.2;
        evidence.push(`Import: ${imp}`);
      }
    }

    // Check strings
    for (const str of data.strings) {
      const found = allStrings.some(s => s.toLowerCase().includes(str.toLowerCase()));
      if (found) {
        confidence += 0.1;
        evidence.push(`String: "${str}"`);
      }
    }

    // Check YARA matches
    const yaraMatches = result.yaraMatches || [];
    for (const keyword of data.yaraKeywords) {
      if (yaraMatches.some(m => m.ruleName.toLowerCase().includes(keyword))) {
        confidence += 0.15;
        evidence.push(`YARA: ${keyword}`);
      }
    }

    // Check findings
    for (const finding of findings) {
      if (finding.description && finding.description.toLowerCase().includes(key)) {
        confidence += 0.1;
        evidence.push(`Finding: ${finding.description}`);
      }
    }

    // Cap confidence at 1.0
    confidence = Math.min(confidence, 1.0);

    if (confidence > 0.2 && evidence.length > 0) {
      matchedCapabilities[key] = {
        type: data.type,
        confidence,
        evidence: evidence.slice(0, 5),
      };
    }
  }

  // Create behavior objects
  for (const [key, data] of Object.entries(matchedCapabilities)) {
    const severity = data.confidence > 0.7 ? 'high' : data.confidence > 0.4 ? 'medium' : 'low';
    const categoryName = key.replace(/_/g, ' ');
    behaviors.push({
      type: data.type,
      description: `Static indicators suggest potential ${categoryName} capability`,
      severity: severity,
      confidence: data.confidence,
      evidence: data.evidence,
      source: 'static_analysis',
      timestamp: new Date(),
    });
  }

  return behaviors;
}

  /**
   * Save behaviors to database
   */
  static async _saveBehaviors(analysisId, sampleId, behaviors) {
    const Behavior = require('../models/Behavior');
    const saved = [];

    for (const behavior of behaviors) {
      const newBehavior = new Behavior({
        type: behavior.type,
        description: behavior.description,
        severity: behavior.severity,
        confidence: behavior.confidence,
        evidence: behavior.evidence,
        source: 'static_analysis',
        sample: sampleId,
        analysis: analysisId,
        mitre: {}, // Will be enriched later
        tags: [],
      });
      await newBehavior.save();
      saved.push(newBehavior);
    }

    logger.info(`Saved ${saved.length} behaviors for sample ${sampleId}`);
    return saved;
  }

  static async getResults(analysisId) {
    try {
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      if (!analysis.staticAnalysis) {
        throw new ApiError(404, 'Static analysis not found for this analysis');
      }

      const staticAnalysis = await StaticAnalysis.findById(analysis.staticAnalysis)
        .populate('sample', 'filename sha256 md5 fileSize')
        .lean();

      if (!staticAnalysis) {
        throw new ApiError(404, 'Static analysis results not found');
      }

      return staticAnalysis;
    } catch (error) {
      logger.error(`Failed to get static analysis results: ${error.message}`, { error });
      throw error;
    }
  }

  static async getSummary(analysisId) {
    try {
      const results = await this.getResults(analysisId);
      
      return {
        fileInfo: results.fileInfo,
        summary: {
          totalSections: results.sections ? results.sections.length : 0,
          totalImports: results.imports ? results.imports.reduce((acc, imp) => acc + imp.functions.length, 0) : 0,
          totalExports: results.exports ? results.exports.length : 0,
          yaraMatches: results.yaraMatches ? results.yaraMatches.length : 0,
          findings: results.findings ? results.findings.length : 0,
          suspiciousStrings: results.strings && results.strings.suspicious ? results.strings.suspicious.length : 0,
        },
        findings: results.findings || [],
        yaraMatches: results.yaraMatches || [],
        processedAt: results.processedAt,
      };
    } catch (error) {
      logger.error(`Failed to get static analysis summary: ${error.message}`, { error });
      throw error;
    }
  }

  static async hasResults(sampleId) {
    try {
      const count = await StaticAnalysis.countDocuments({ sample: sampleId });
      return count > 0;
    } catch (error) {
      logger.error(`Failed to check static analysis results: ${error.message}`, { error });
      return false;
    }
  }
}

module.exports = StaticAnalysisService;