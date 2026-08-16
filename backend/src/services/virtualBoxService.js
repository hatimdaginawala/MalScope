const { exec } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');
const execPromise = util.promisify(exec);
const logger = require('../utils/logger');
const environment = require('../config/environment');

class VirtualBoxService {
  constructor() {
    this.vmName = environment.vm.name || 'MalScope-Windows-Lab';
    this.snapshotName = environment.vm.snapshot || 'MalScope-Clean';
    this.vmUser = environment.vm.user || 'admin';
    this.vmPassword = environment.vm.password || 'password';
    this.vmReady = false;
  }

  /**
   * Execute VBoxManage command
   */
  async _executeVBoxCommand(command, timeout = 30000) {
    try {
      const fullCommand = `VBoxManage ${command}`;
      logger.debug(`Executing VBoxManage: ${fullCommand}`);
      
      const { stdout, stderr } = await execPromise(fullCommand, { timeout });
      
      if (stderr && !stderr.includes('WARNING')) {
        logger.warn(`VBoxManage stderr: ${stderr}`);
      }
      
      return { stdout, stderr };
    } catch (error) {
      logger.error(`VBoxManage command failed: ${error.message}`, { command, error });
      throw new Error(`VirtualBox command failed: ${error.message}`);
    }
  }

  /**
   * Check if VirtualBox is available
   */
  async isVirtualBoxAvailable() {
    try {
      await this._executeVBoxCommand('--version', 5000);
      return true;
    } catch (error) {
      logger.error('VirtualBox not available', { error: error.message });
      return false;
    }
  }

  /**
   * Check if VM exists
   */
  async vmExists() {
    try {
      const { stdout } = await this._executeVBoxCommand(`list vms`, 10000);
      return stdout.includes(this.vmName);
    } catch (error) {
      logger.error(`Failed to check VM existence: ${error.message}`, { error });
      return false;
    }
  }

  /**
   * Get VM state
   */
  async getVMState() {
    try {
      const { stdout } = await this._executeVBoxCommand(`showvminfo "${this.vmName}" --machinereadable`, 10000);
      const lines = stdout.split('\n');
      for (const line of lines) {
        if (line.startsWith('VMState=')) {
          const state = line.replace('VMState="', '').replace('"', '').trim();
          return state;
        }
      }
      return 'unknown';
    } catch (error) {
      logger.error(`Failed to get VM state: ${error.message}`, { error });
      return 'unknown';
    }
  }

  /**
   * Check if snapshot exists
   */
  async snapshotExists(snapshotName = null) {
    const snap = snapshotName || this.snapshotName;
    try {
      const { stdout } = await this._executeVBoxCommand(`snapshot "${this.vmName}" list`, 10000);
      return stdout.includes(snap);
    } catch (error) {
      logger.error(`Failed to check snapshot: ${error.message}`, { error });
      return false;
    }
  }

  /**
   * Restore VM to snapshot
   */
  async restoreSnapshot(snapshotName = null) {
    const snap = snapshotName || this.snapshotName;
    
    try {
      // Check if VM exists
      if (!await this.vmExists()) {
        throw new Error(`VM "${this.vmName}" does not exist`);
      }

      // Check if snapshot exists
      if (!await this.snapshotExists(snap)) {
        throw new Error(`Snapshot "${snap}" does not exist for VM "${this.vmName}"`);
      }

      // Power off VM if running
      const state = await this.getVMState();
      if (state === 'running') {
        logger.info(`Powering off VM: ${this.vmName}`);
        await this._executeVBoxCommand(`controlvm "${this.vmName}" poweroff`, 30000);
      }

      // Restore snapshot
      logger.info(`Restoring VM "${this.vmName}" to snapshot "${snap}"`);
      await this._executeVBoxCommand(`snapshot "${this.vmName}" restore "${snap}"`, 60000);
      
      this.vmReady = false;
      logger.info(`VM restored to snapshot: ${snap}`);
      return true;
    } catch (error) {
      logger.error(`Failed to restore snapshot: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Start VM
   */
  async startVM() {
    try {
      const state = await this.getVMState();
      
      if (state === 'running') {
        logger.info(`VM "${this.vmName}" is already running`);
        return true;
      }

      if (state === 'saved') {
        logger.info(`Starting saved VM: ${this.vmName}`);
        await this._executeVBoxCommand(`startvm "${this.vmName}" --type headless`, 30000);
      } else {
        logger.info(`Starting VM: ${this.vmName}`);
        await this._executeVBoxCommand(`startvm "${this.vmName}" --type headless`, 30000);
      }

      // Wait for VM to be ready
      await this._waitForVMReady();
      
      this.vmReady = true;
      logger.info(`VM "${this.vmName}" started successfully`);
      return true;
    } catch (error) {
      logger.error(`Failed to start VM: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Wait for VM to be ready
   */
  async _waitForVMReady(timeout = 60000) {
    const startTime = Date.now();
    let ready = false;
    
    while (!ready && (Date.now() - startTime) < timeout) {
      try {
        const state = await this.getVMState();
        if (state === 'running') {
          ready = true;
          break;
        }
        // Wait 5 seconds before checking again
        await new Promise(resolve => setTimeout(resolve, 5000));
      } catch (error) {
        // Ignore errors and retry
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }

    if (!ready) {
      throw new Error(`VM did not become ready within ${timeout}ms`);
    }

    // Additional wait for guest services to initialize
    await new Promise(resolve => setTimeout(resolve, 10000));
  }

  /**
   * Stop VM
   */
  async stopVM() {
    try {
      const state = await this.getVMState();
      
      if (state === 'poweroff' || state === 'saved') {
        logger.info(`VM "${this.vmName}" is already stopped`);
        return true;
      }

      logger.info(`Stopping VM: ${this.vmName}`);
      await this._executeVBoxCommand(`controlvm "${this.vmName}" acpipowerbutton`, 30000);
      
      // Wait for VM to stop
      await this._waitForVMStop();
      
      this.vmReady = false;
      logger.info(`VM "${this.vmName}" stopped successfully`);
      return true;
    } catch (error) {
      logger.error(`Failed to stop VM: ${error.message}`, { error });
      
      // Force power off if graceful shutdown fails
      try {
        await this._executeVBoxCommand(`controlvm "${this.vmName}" poweroff`, 30000);
        logger.info(`VM "${this.vmName}" forced power off`);
      } catch (forceError) {
        logger.error(`Failed to force power off VM: ${forceError.message}`);
      }
      
      throw error;
    }
  }

  /**
   * Wait for VM to stop
   */
  async _waitForVMStop(timeout = 60000) {
    const startTime = Date.now();
    let stopped = false;
    
    while (!stopped && (Date.now() - startTime) < timeout) {
      try {
        const state = await this.getVMState();
        if (state === 'poweroff' || state === 'saved') {
          stopped = true;
          break;
        }
        await new Promise(resolve => setTimeout(resolve, 5000));
      } catch (error) {
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }

    if (!stopped) {
      throw new Error(`VM did not stop within ${timeout}ms`);
    }
  }

  /**
   * Restore VM to clean state (restore snapshot + start)
   */
  async restoreCleanState() {
    try {
      // First, stop VM if running
      const state = await this.getVMState();
      if (state === 'running') {
        await this.stopVM();
      }

      // Restore snapshot
      await this.restoreSnapshot();

      // Start VM
      await this.startVM();

      logger.info(`VM restored to clean state`);
      return true;
    } catch (error) {
      logger.error(`Failed to restore clean state: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Execute command in VM via guest control
   */
  async executeGuestCommand(command, timeout = 30000) {
    try {
      // Check if guest additions are available
      const { stdout } = await this._executeVBoxCommand(
        `guestcontrol "${this.vmName}" run --username "${this.vmUser}" --password "${this.vmPassword}" --wait-stdout --wait-stderr --timeout ${timeout} cmd.exe /c "${command}"`,
        timeout + 5000
      );
      
      return { stdout };
    } catch (error) {
      logger.error(`Failed to execute guest command: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Copy file to VM
   */
  async copyToGuest(hostPath, guestPath, timeout = 60000) {
    try {
      if (!fs.existsSync(hostPath)) {
        throw new Error(`Host file not found: ${hostPath}`);
      }

      // Create directory in guest
      const dir = path.dirname(guestPath);
      await this.executeGuestCommand(`mkdir ${dir} 2>nul`, 10000);

      // Copy file
      await this._executeVBoxCommand(
        `guestcontrol "${this.vmName}" copyto "${hostPath}" "${guestPath}" --username "${this.vmUser}" --password "${this.vmPassword}"`,
        timeout
      );

      logger.info(`File copied to guest: ${hostPath} -> ${guestPath}`);
      return true;
    } catch (error) {
      logger.error(`Failed to copy file to guest: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Copy file from VM
   */
  async copyFromGuest(guestPath, hostPath, timeout = 60000) {
    try {
      await this._executeVBoxCommand(
        `guestcontrol "${this.vmName}" copyfrom "${guestPath}" "${hostPath}" --username "${this.vmUser}" --password "${this.vmPassword}"`,
        timeout
      );

      logger.info(`File copied from guest: ${guestPath} -> ${hostPath}`);
      return true;
    } catch (error) {
      logger.error(`Failed to copy file from guest: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Check if VM is ready for analysis
   */
  async isVMReady() {
    try {
      if (this.vmReady) return true;
      
      const state = await this.getVMState();
      return state === 'running';
    } catch (error) {
      return false;
    }
  }

  /**
   * Get VM configuration
   */
  async getVMConfig() {
    try {
      const { stdout } = await this._executeVBoxCommand(`showvminfo "${this.vmName}" --machinereadable`, 10000);
      const config = {};
      
      const lines = stdout.split('\n');
      for (const line of lines) {
        const parts = line.split('=');
        if (parts.length === 2) {
          const key = parts[0].trim();
          const value = parts[1].replace(/^"/, '').replace(/"$/, '').trim();
          config[key] = value;
        }
      }
      
      return config;
    } catch (error) {
      logger.error(`Failed to get VM config: ${error.message}`, { error });
      return null;
    }
  }
}

module.exports = new VirtualBoxService();