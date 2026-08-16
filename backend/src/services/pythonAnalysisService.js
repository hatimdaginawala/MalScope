const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class PythonAnalysisService {
  constructor() {
    this.pythonPath = this._findPython();
    this.workerPath = path.join(process.cwd(), '..', 'analysis-engine', 'worker.py');
    
    // Fallback if running from backend directory
    if (!fs.existsSync(this.workerPath)) {
      this.workerPath = path.join(process.cwd(), 'analysis-engine', 'worker.py');
    }
    
    // Default timeout: 5 minutes for static, 30 minutes for dynamic
    this.defaultTimeouts = {
      static: 5 * 60 * 1000,
      dynamic: 30 * 60 * 1000,
      test: 10 * 1000,
    };
  }

  /**
   * Find Python executable
   */
  _findPython() {
    // Try common Python executable names
    const pythonCandidates = ['python3', 'python', 'py'];
    
    for (const candidate of pythonCandidates) {
      try {
        // Simple check - will throw if not found
        const result = require('child_process').spawnSync(candidate, ['--version']);
        if (result.status === 0) {
          return candidate;
        }
      } catch (error) {
        // Continue to next candidate
      }
    }
    
    // Default to 'python' and let it fail if not found
    return 'python';
  }

  /**
   * Execute Python worker
   */
  async executeWorker(args, timeout = null) {
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      const timeoutMs = timeout || this.defaultTimeouts.static;

      // Build command arguments
      const cmdArgs = [];
      for (const [key, value] of Object.entries(args)) {
        cmdArgs.push(`--${key}`);
        if (value !== null && value !== undefined) {
          cmdArgs.push(String(value));
        }
      }

      logger.debug(`Executing Python worker: ${this.pythonPath} ${this.workerPath} ${cmdArgs.join(' ')}`);

      const child = spawn(this.pythonPath, [this.workerPath, ...cmdArgs]);

      let stdout = '';
      let stderr = '';

      child.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      child.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      // Set timeout
      const timeoutId = setTimeout(() => {
        child.kill('SIGTERM');
        reject(new Error(`Python worker timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      child.on('close', (code) => {
        clearTimeout(timeoutId);
        const duration = Date.now() - startTime;

        if (stderr) {
          logger.warn(`Python worker stderr: ${stderr}`);
        }

        if (code !== 0) {
          const error = new Error(`Python worker exited with code ${code}`);
          error.stderr = stderr;
          error.stdout = stdout;
          reject(error);
          return;
        }

        try {
          // Parse JSON output
          const result = JSON.parse(stdout);
          resolve({
            success: true,
            data: result,
            duration,
            stdout,
            stderr,
          });
        } catch (error) {
          reject(new Error(`Failed to parse Python output: ${error.message}\nOutput: ${stdout}`));
        }
      });

      child.on('error', (error) => {
        clearTimeout(timeoutId);
        reject(new Error(`Failed to start Python worker: ${error.message}`));
      });
    });
  }

  /**
   * Run static analysis on a sample
   */
  async runStaticAnalysis(samplePath, options = {}) {
    try {
      if (!fs.existsSync(samplePath)) {
        throw new ApiError(404, `Sample file not found: ${samplePath}`);
      }

      logger.info(`Running static analysis on: ${samplePath}`);

      const result = await this.executeWorker({
        mode: 'static',
        sample: samplePath,
        ...options,
      }, options.timeout || this.defaultTimeouts.static);

      return result.data;
    } catch (error) {
      logger.error(`Static analysis failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Run dynamic analysis on telemetry data
   */
  async runDynamicAnalysis(telemetryPath, options = {}) {
    try {
      if (!fs.existsSync(telemetryPath)) {
        throw new ApiError(404, `Telemetry file not found: ${telemetryPath}`);
      }

      logger.info(`Running dynamic analysis on: ${telemetryPath}`);

      const result = await this.executeWorker({
        mode: 'dynamic',
        telemetry: telemetryPath,
        ...options,
      }, options.timeout || this.defaultTimeouts.dynamic);

      return result.data;
    } catch (error) {
      logger.error(`Dynamic analysis failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Test the Python worker
   */
  async testWorker() {
    try {
      logger.info('Testing Python worker...');

      const result = await this.executeWorker({
        mode: 'test',
      }, this.defaultTimeouts.test);

      logger.info('Python worker test successful', { result: result.data });
      return result.data;
    } catch (error) {
      logger.error(`Python worker test failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Check if Python worker is available
   */
  async isAvailable() {
    try {
      await this.testWorker();
      return true;
    } catch (error) {
      return false;
    }
  }
}

module.exports = new PythonAnalysisService();