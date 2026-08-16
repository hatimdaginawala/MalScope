const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const MalwareSample = require('../models/MalwareSample');
const { Analysis, ANALYSIS_STATUS } = require('../models/Analysis');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');
const fileUtils = require('../utils/fileUtils');

class SampleService {
  /**
   * Calculate hashes for a file
   */
  static async calculateHashes(fileBuffer) {
    const sha256 = crypto.createHash('sha256').update(fileBuffer).digest('hex');
    const md5 = crypto.createHash('md5').update(fileBuffer).digest('hex');
    const sha1 = crypto.createHash('sha1').update(fileBuffer).digest('hex');
    return { sha256, md5, sha1 };
  }

  /**
   * Detect file type
   */
  static detectFileType(buffer) {
    // Check for PE signature
    if (buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) {
      // MZ header
      return 'pe';
    }
    // Check for ELF signature
    if (buffer.length >= 4 && buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
      return 'elf';
    }
    return 'unknown';
  }

  /**
   * Detect PE subtype
   */
  static detectPESubtype(buffer) {
    try {
      // Read PE header at offset 0x3C
      const peOffset = buffer.readUInt16LE(0x3C);
      if (peOffset + 4 > buffer.length) return 'unknown';

      // Check PE signature
      if (buffer.readUInt32LE(peOffset) !== 0x00004550) return 'unknown';

      // Read characteristics at offset peOffset + 0x16
      const characteristics = buffer.readUInt16LE(peOffset + 0x16);
      
      if (characteristics & 0x2000) return 'dll'; // IMAGE_FILE_DLL
      if (characteristics & 0x0002) return 'exe'; // IMAGE_FILE_EXECUTABLE_IMAGE
      if (characteristics & 0x0100) return 'sys'; // IMAGE_FILE_SYSTEM
      
      return 'exe';
    } catch (error) {
      return 'unknown';
    }
  }

  /**
   * Determine architecture from PE header
   */
  static detectArchitecture(buffer) {
    try {
      const peOffset = buffer.readUInt16LE(0x3C);
      const machine = buffer.readUInt16LE(peOffset + 4);
      
      if (machine === 0x8664) return 'x64'; // IMAGE_FILE_MACHINE_AMD64
      if (machine === 0x14C) return 'x86'; // IMAGE_FILE_MACHINE_I386
      if (machine === 0x200) return 'x86'; // IMAGE_FILE_MACHINE_IA64
      if (machine === 0xAA64) return 'x64'; // IMAGE_FILE_MACHINE_ARM64
      
      return 'unknown';
    } catch (error) {
      return 'unknown';
    }
  }

  /**
   * Upload and process a new sample
   */
  static async uploadSample(fileBuffer, filename, userId = null) {
    try {
      // Validate file size (e.g., 100MB limit)
      const MAX_SIZE = 100 * 1024 * 1024; // 100MB
      if (fileBuffer.length > MAX_SIZE) {
        throw new ApiError(413, `File exceeds maximum size of ${MAX_SIZE / 1024 / 1024}MB`);
      }

      // Calculate hashes
      const hashes = await this.calculateHashes(fileBuffer);

      // Check for duplicate
      const existing = await MalwareSample.findOne({ sha256: hashes.sha256 });
      if (existing) {
        return {
          duplicate: true,
          sample: existing,
          message: 'Sample already exists in the system',
        };
      }

      // Detect file type
      const fileType = this.detectFileType(fileBuffer);
      if (fileType !== 'pe') {
        throw new ApiError(400, `Unsupported file type: ${fileType}. Currently only PE files are supported.`);
      }

      // Detect PE subtype and architecture
      const peType = this.detectPESubtype(fileBuffer);
      const arch = this.detectArchitecture(fileBuffer);

      // Generate storage path
      const storageDir = path.join(process.cwd(), 'storage', 'samples', 'pending');
      await fs.promises.mkdir(storageDir, { recursive: true });

      const safeFilename = `${hashes.sha256}.exe`;
      const storagePath = path.join(storageDir, safeFilename);

      // Write file
      await fs.promises.writeFile(storagePath, fileBuffer);

      // Create sample record
      const sample = new MalwareSample({
        filename,
        originalFilename: filename,
        sha256: hashes.sha256,
        md5: hashes.md5,
        sha1: hashes.sha1,
        fileSize: fileBuffer.length,
        fileType,
        peType,
        arch,
        mimeType: 'application/x-msdownload',
        storagePath,
        submittedBy: userId,
        status: 'pending',
      });

      await sample.save();

      // Create analysis record
      const analysis = new Analysis({
        sample: sample._id,
        status: ANALYSIS_STATUS.QUEUED,
        stage: ANALYSIS_STATUS.QUEUED,
        environment: {
          nodeVersion: process.version,
        },
      });

      await analysis.save();

      logger.info(`Sample uploaded: ${hashes.sha256} (${filename})`);

      return {
        duplicate: false,
        sample,
        analysis,
        hashes,
      };
    } catch (error) {
      logger.error(`Sample upload failed: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get all samples with pagination
   */
  static async getSamples(page = 1, limit = 20, filters = {}) {
    try {
      const skip = (page - 1) * limit;
      
      // Build query
      const query = {};
      if (filters.status) query.status = filters.status;
      if (filters.fileType) query.fileType = filters.fileType;
      if (filters.search) {
        query.$or = [
          { filename: { $regex: filters.search, $options: 'i' } },
          { sha256: { $regex: filters.search } },
          { md5: { $regex: filters.search } },
        ];
      }

      const [samples, total] = await Promise.all([
        MalwareSample.find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .populate('submittedBy', 'username')
          .lean(),
        MalwareSample.countDocuments(query),
      ]);

      return {
        samples,
        pagination: {
          page,
          limit,
          total,
          pages: Math.ceil(total / limit),
        },
      };
    } catch (error) {
      logger.error(`Failed to get samples: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get sample by ID
   */
  static async getSampleById(sampleId) {
    try {
      const sample = await MalwareSample.findById(sampleId)
        .populate('submittedBy', 'username')
        .lean();

      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      return sample;
    } catch (error) {
      logger.error(`Failed to get sample: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get sample by hash
   */
  static async getSampleByHash(hash) {
    try {
      const sample = await MalwareSample.findByHash(hash);
      return sample;
    } catch (error) {
      logger.error(`Failed to get sample by hash: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Delete sample
   */
  static async deleteSample(sampleId) {
    try {
      const sample = await MalwareSample.findById(sampleId);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      // Delete file from storage
      try {
        await fs.promises.unlink(sample.storagePath);
      } catch (err) {
        logger.warn(`Failed to delete sample file: ${sample.storagePath}`, { error: err.message });
      }

      // Delete related analyses
      await Analysis.deleteMany({ sample: sample._id });

      // Delete the sample
      await sample.deleteOne();

      logger.info(`Sample deleted: ${sample.sha256}`);
      return { success: true, message: 'Sample deleted successfully' };
    } catch (error) {
      logger.error(`Failed to delete sample: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Update sample status
   */
  static async updateStatus(sampleId, status) {
    try {
      const sample = await MalwareSample.findById(sampleId);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      sample.status = status;
      await sample.save();

      return sample;
    } catch (error) {
      logger.error(`Failed to update sample status: ${error.message}`, { error });
      throw error;
    }
  }
}

module.exports = SampleService;