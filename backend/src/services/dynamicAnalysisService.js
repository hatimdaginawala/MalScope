const DynamicAnalysis = require('../models/DynamicAnalysis');
const MalwareSample = require('../models/MalwareSample');
const AnalysisService = require('./analysisService');
const PythonAnalysisService = require('./pythonAnalysisService');
const VirtualBoxService = require('./virtualBoxService');
const TelemetryService = require('./telemetryService');
const IOCService = require('./iocService');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');
const fs = require('fs');
const path = require('path');

class DynamicAnalysisService {
  /**
   * Perform dynamic analysis on a sample
   */
  static async analyze(analysisId, options = {}) {
    try {
      // Get analysis
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      // Check if we can proceed
      const canProceed = await AnalysisService.canProceed(analysisId);
      if (!canProceed) {
        throw new ApiError(400, `Analysis cannot proceed in current state: ${analysis.status}`);
      }

      // Update status
      await AnalysisService.updateStatus(analysisId, 'dynamic_analysis', 'Starting dynamic analysis');

      // Get sample
      const sample = await MalwareSample.findById(analysis.sample);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      // Ensure sample file exists
      if (!fs.existsSync(sample.storagePath)) {
        throw new ApiError(404, `Sample file not found: ${sample.storagePath}`);
      }

      // Check VirtualBox availability
      const vboxAvailable = await VirtualBoxService.isVirtualBoxAvailable();
      if (!vboxAvailable) {
        throw new ApiError(503, 'VirtualBox is not available');
      }

      // Check VM availability
      const vmExists = await VirtualBoxService.vmExists();
      if (!vmExists) {
        throw new ApiError(503, 'VM not found');
      }

      // Check snapshot availability
      const snapshotExists = await VirtualBoxService.snapshotExists();
      if (!snapshotExists) {
        throw new ApiError(503, 'VM snapshot not found');
      }

      // Update status
      await AnalysisService.updateStatus(analysisId, 'preparing', 'Preparing VM for analysis');

      // Restore VM to clean state
      await VirtualBoxService.restoreCleanState();

      // Update status
      await AnalysisService.updateStatus(analysisId, 'dynamic_analysis', 'VM ready, transferring sample');

      // Generate guest paths
      const guestFilename = `sample_${sample.sha256.substring(0, 8)}.exe`;
      const guestPath = `C:\\Temp\\${guestFilename}`;
      const telemetryDir = `C:\\Temp\\${analysisId}`;

      // Create telemetry directory in guest
      await VirtualBoxService.executeGuestCommand(`mkdir ${telemetryDir} 2>nul`);

      // Transfer sample to VM
      await VirtualBoxService.copyToGuest(sample.storagePath, guestPath);

      // Update status
      await AnalysisService.updateStatus(analysisId, 'dynamic_analysis', 'Sample transferred, starting execution');

      // Start telemetry collection
      await VirtualBoxService.executeGuestCommand(
        `powershell -Command "Start-Process -FilePath '${guestPath}' -WindowStyle Hidden"`,
        5000
      );

      // Wait for execution with timeout
      const executionTimeout = options.executionTimeout || 60000; // 60 seconds default
      await AnalysisService.updateStatus(analysisId, 'collecting', `Executing sample with ${executionTimeout}ms timeout`);

      // Wait for execution
      await this._waitForExecution(executionTimeout);

      // Stop telemetry collection
      await AnalysisService.updateStatus(analysisId, 'collecting', 'Collecting telemetry data');

      // Collect telemetry (this is a simplified example - actual collection would be more complex)
      const telemetry = await this._collectTelemetry(analysisId, sample);

      // Save telemetry
      const telemetryResult = await TelemetryService.saveTelemetry(analysisId, telemetry);

      // Process telemetry with Python
      await AnalysisService.updateStatus(analysisId, 'correlating', 'Processing telemetry data');

      let pythonResult;
      try {
        pythonResult = await PythonAnalysisService.runDynamicAnalysis(telemetryResult.filePath);
      } catch (error) {
        await AnalysisService.setError(analysisId, `Python analysis failed: ${error.message}`, 'dynamic_analysis');
        throw error;
      }

      // Create DynamicAnalysis record
      const dynamicAnalysis = new DynamicAnalysis({
        sample: sample._id,
        analysis: analysisId,
        environment: {
          vmName: VirtualBoxService.vmName,
          snapshot: VirtualBoxService.snapshotName,
          executionTimeout,
          networkEnabled: false,
          osVersion: 'Windows 10', // Would be detected from VM
        },
        processes: pythonResult.result.processes || [],
        fileEvents: pythonResult.result.fileEvents || [],
        registryEvents: pythonResult.result.registryEvents || [],
        persistence: pythonResult.result.persistence || [],
        networkEvents: pythonResult.result.networkEvents || [],
        behaviors: pythonResult.result.behaviors || [],
        execution: {
          startedAt: new Date(Date.now() - executionTimeout),
          endedAt: new Date(),
          duration: executionTimeout,
          exitCode: 0,
          timeout: false,
        },
        telemetrySource: 'sysmon',
        processedAt: new Date(),
        processingDuration: pythonResult.duration || 0,
        warnings: pythonResult.warnings || [],
        errors: pythonResult.errors || [],
        version: '1.0.0',
      });

      await dynamicAnalysis.save();

      // Extract IOCs from dynamic analysis
      const iocs = await IOCService.extractIOCs(analysisId, sample._id, {
        dynamic: dynamicAnalysis,
      });

      // Update analysis with dynamicAnalysis reference
      analysis.dynamicAnalysis = dynamicAnalysis._id;
      await analysis.save();

      // Cleanup - restore VM
      await AnalysisService.updateStatus(analysisId, 'cleanup', 'Cleaning up VM');
      await VirtualBoxService.restoreCleanState();

      await AnalysisService.addLog(analysisId, 'Dynamic analysis completed successfully', 'info');

      return {
        dynamicAnalysis,
        pythonResult,
        iocs,
        warnings: pythonResult.warnings || [],
        errors: pythonResult.errors || [],
      };
    } catch (error) {
      // Cleanup on error
      try {
        await VirtualBoxService.restoreCleanState();
      } catch (cleanupError) {
        logger.error(`Cleanup failed: ${cleanupError.message}`);
      }

      logger.error(`Dynamic analysis failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Wait for execution to complete
   */
  static async _waitForExecution(timeout) {
    // This is a simplified wait - in reality, we'd monitor the VM for completion
    return new Promise((resolve) => {
      setTimeout(resolve, Math.min(timeout, 60000));
    });
  }

  /**
   * Collect telemetry from VM
   */
  static async _collectTelemetry(analysisId, sample) {
    // This is a simplified telemetry collection - actual collection would parse Sysmon logs
    return {
      analysisId,
      sampleSha256: sample.sha256,
      collectedAt: new Date().toISOString(),
      source: 'sysmon',
      processes: [
        {
          pid: 1234,
          ppid: 5678,
          name: 'sample.exe',
          path: `C:\\Temp\\${analysisId}\\sample.exe`,
          commandLine: `C:\\Temp\\${analysisId}\\sample.exe`,
          startTime: new Date().toISOString(),
        },
      ],
      fileEvents: [
        {
          path: 'C:\\Users\\Public\\test.txt',
          operation: 'create',
          processId: 1234,
          processName: 'sample.exe',
          timestamp: new Date().toISOString(),
        },
      ],
      registryEvents: [],
      networkEvents: [],
      persistence: [],
    };
  }

  /**
   * Get dynamic analysis results
   */
  static async getResults(analysisId) {
    try {
      const analysis = await AnalysisService.getAnalysisById(analysisId);
      if (!analysis) {
        throw new ApiError(404, 'Analysis not found');
      }

      if (!analysis.dynamicAnalysis) {
        throw new ApiError(404, 'Dynamic analysis not found for this analysis');
      }

      const dynamicAnalysis = await DynamicAnalysis.findById(analysis.dynamicAnalysis)
        .populate('sample', 'filename sha256 md5 fileSize')
        .lean();

      if (!dynamicAnalysis) {
        throw new ApiError(404, 'Dynamic analysis results not found');
      }

      return dynamicAnalysis;
    } catch (error) {
      logger.error(`Failed to get dynamic analysis results: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get dynamic analysis summary
   */
  static async getSummary(analysisId) {
    try {
      const results = await this.getResults(analysisId);

      return {
        summary: {
          processes: results.processes ? results.processes.length : 0,
          fileEvents: results.fileEvents ? results.fileEvents.length : 0,
          registryEvents: results.registryEvents ? results.registryEvents.length : 0,
          networkEvents: results.networkEvents ? results.networkEvents.length : 0,
          persistence: results.persistence ? results.persistence.length : 0,
          behaviors: results.behaviors ? results.behaviors.length : 0,
        },
        execution: results.execution || {},
        behaviors: results.behaviors || [],
        networkEvents: results.networkEvents || [],
        persistence: results.persistence || [],
        warnings: results.warnings || [],
        errors: results.errors || [],
        processedAt: results.processedAt,
      };
    } catch (error) {
      logger.error(`Failed to get dynamic analysis summary: ${error.message}`, { error });
      throw error;
    }
  }
}

module.exports = DynamicAnalysisService;