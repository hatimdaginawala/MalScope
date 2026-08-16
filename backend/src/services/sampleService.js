const fs = require('fs');
const path = require('path');
const MalwareSample = require('../models/MalwareSample');
const { Analysis, ANALYSIS_STATUS } = require('../models/Analysis');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');
const fileUtils = require('../utils/fileUtils');

class SampleService {
  /**
   * Calculate hashes for a file buffer
   */
  static async calculateHashes(buffer) {
    return fileUtils.calculateHashes(buffer);
  }

  /**
   * Detect file type from buffer
   */
  static detectFileType(buffer) {
    return fileUtils.detectFileType(buffer);
  }

  /**
   * Detect PE subtype from buffer
   */
  static detectPESubtype(buffer) {
    return fileUtils.detectPESubtype(buffer);
  }

  /**
   * Detect architecture from buffer
   */
  static detectArchitecture(buffer) {
    return fileUtils.detectArchitecture(buffer);
  }

  /**
   * Upload and process a new sample
   */
static async uploadSample(fileBuffer, filename, userId = null) {
    try {
      // Check if fileBuffer is valid
      if (!fileBuffer || !Buffer.isBuffer(fileBuffer)) {
        throw new ApiError(400, 'Invalid file buffer');
      }

      // Validate file size (100MB limit)
      const MAX_SIZE = 100 * 1024 * 1024;
      if (fileBuffer.length > MAX_SIZE) {
        throw new ApiError(413, `File exceeds maximum size of ${MAX_SIZE / 1024 / 1024}MB`);
      }

      // Validate file is not empty
      if (fileBuffer.length === 0) {
        throw new ApiError(400, 'File is empty');
      }

      // Calculate hashes
      const hashes = await this.calculateHashes(fileBuffer);

      // Check for duplicate
      const existing = await MalwareSample.findOne({ sha256: hashes.sha256 });
      if (existing) {
        const existingAnalysis = await Analysis.findOne({ 
          sample: existing._id,
          status: { $nin: ['completed', 'failed'] }
        });

        return {
          duplicate: true,
          sample: existing,
          analysis: existingAnalysis,
          message: 'Sample already exists in the system',
        };
      }

      // Detect file type
      const fileType = this.detectFileType(fileBuffer);
      
      // For now, allow any file type for testing
      // In production, we would restrict to PE files
      // if (fileType !== 'pe') {
      //   throw new ApiError(400, `Unsupported file type: ${fileType}. Currently only PE files are supported.`);
      // }

      // Detect PE subtype and architecture
      const peType = this.detectPESubtype(fileBuffer);
      const arch = this.detectArchitecture(fileBuffer);
      const mimeType = fileUtils.getMimeType(filename);

      // Generate storage path
      const storageDir = path.join(process.cwd(), 'storage', 'samples', 'pending');
      fileUtils.ensureDirectory(storageDir);

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
        fileType: fileType || 'unknown',
        peType: peType,
        arch: arch,
        mimeType,
        storagePath,
        submittedBy: userId,
        status: 'pending',
        tags: [],
        metadata: {
          uploadedAt: new Date().toISOString(),
          originalName: filename,
        },
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
        startedAt: new Date(),
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
   * Get all samples with pagination and filters
   */
  static async getSamples(page = 1, limit = 20, filters = {}) {
    try {
      const skip = (page - 1) * limit;
      
      // Build query
      const query = {};
      
      // Status filter
      if (filters.status) {
        query.status = filters.status;
      }
      
      // File type filter
      if (filters.fileType) {
        query.fileType = filters.fileType;
      }
      
      // PE type filter
      if (filters.peType) {
        query.peType = filters.peType;
      }
      
      // Architecture filter
      if (filters.arch) {
        query.arch = filters.arch;
      }

      // Search filter (filename or hash)
      if (filters.search) {
        query.$or = [
          { filename: { $regex: filters.search, $options: 'i' } },
          { sha256: { $regex: filters.search } },
          { md5: { $regex: filters.search } },
          { sha1: { $regex: filters.search } },
        ];
      }

      // Date range filter
      if (filters.startDate) {
        query.createdAt = { $gte: new Date(filters.startDate) };
      }
      if (filters.endDate) {
        query.createdAt = { ...query.createdAt, $lte: new Date(filters.endDate) };
      }

      const [samples, total] = await Promise.all([
        MalwareSample.find(query)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .populate('submittedBy', 'username email')
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
   * Get sample by ID with related data
   */
  static async getSampleById(sampleId) {
    try {
      const sample = await MalwareSample.findById(sampleId)
        .populate('submittedBy', 'username email')
        .lean();

      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      // Get latest analysis
      const latestAnalysis = await Analysis.findOne({ sample: sampleId })
        .sort({ createdAt: -1 })
        .populate('staticAnalysis')
        .populate('dynamicAnalysis')
        .populate('virusTotalReport')
        .populate('threatAssessment')
        .lean();

      return {
        ...sample,
        latestAnalysis,
      };
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
   * Delete sample and all related data
   */
  static async deleteSample(sampleId) {
    try {
      const sample = await MalwareSample.findById(sampleId);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      // Delete file from storage
      await fileUtils.deleteFile(sample.storagePath);

      // Delete related analyses
      await Analysis.deleteMany({ sample: sample._id });

      // Delete related static analyses
      const StaticAnalysis = require('../models/StaticAnalysis');
      await StaticAnalysis.deleteMany({ sample: sample._id });

      // Delete related dynamic analyses
      const DynamicAnalysis = require('../models/DynamicAnalysis');
      await DynamicAnalysis.deleteMany({ sample: sample._id });

      // Delete related IOCs
      const IOC = require('../models/IOC');
      await IOC.deleteMany({ sample: sample._id });

      // Delete related behaviors
      const Behavior = require('../models/Behavior');
      await Behavior.deleteMany({ sample: sample._id });

      // Delete related threat assessments
      const ThreatAssessment = require('../models/ThreatAssessment');
      await ThreatAssessment.deleteMany({ sample: sample._id });

      // Delete virus total reports
      const VirusTotalReport = require('../models/VirusTotalReport');
      await VirusTotalReport.deleteMany({ sample: sample._id });

      // Delete the sample
      await sample.deleteOne();

      logger.info(`Sample deleted: ${sample.sha256}`);
      return { 
        success: true, 
        message: 'Sample and all related data deleted successfully' 
      };
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

      const validStatuses = ['pending', 'processing', 'completed', 'failed'];
      if (!validStatuses.includes(status)) {
        throw new ApiError(400, `Invalid status: ${status}. Must be one of: ${validStatuses.join(', ')}`);
      }

      sample.status = status;
      await sample.save();

      logger.info(`Sample status updated: ${sample.sha256} -> ${status}`);
      return sample;
    } catch (error) {
      logger.error(`Failed to update sample status: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Get sample statistics
   */
  static async getStats() {
    try {
      const [total, byStatus, byType, byPetype, byArch] = await Promise.all([
        MalwareSample.countDocuments(),
        MalwareSample.aggregate([
          { $group: { _id: '$status', count: { $sum: 1 } } },
        ]),
        MalwareSample.aggregate([
          { $group: { _id: '$fileType', count: { $sum: 1 } } },
        ]),
        MalwareSample.aggregate([
          { $group: { _id: '$peType', count: { $sum: 1 } } },
        ]),
        MalwareSample.aggregate([
          { $group: { _id: '$arch', count: { $sum: 1 } } },
        ]),
      ]);

      return {
        total,
        byStatus: byStatus.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
        byType: byType.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
        byPetype: byPetype.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
        byArch: byArch.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
      };
    } catch (error) {
      logger.error(`Failed to get sample stats: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Search samples
   */
  static async searchSamples(query, page = 1, limit = 20) {
    try {
      const skip = (page - 1) * limit;

      const searchQuery = {
        $or: [
          { filename: { $regex: query, $options: 'i' } },
          { sha256: { $regex: query } },
          { md5: { $regex: query } },
          { sha1: { $regex: query } },
          { tags: { $regex: query, $options: 'i' } },
        ],
      };

      const [samples, total] = await Promise.all([
        MalwareSample.find(searchQuery)
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .populate('submittedBy', 'username')
          .lean(),
        MalwareSample.countDocuments(searchQuery),
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
      logger.error(`Failed to search samples: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Add tags to a sample
   */
  static async addTags(sampleId, tags) {
    try {
      const sample = await MalwareSample.findById(sampleId);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      const newTags = Array.isArray(tags) ? tags : [tags];
      const uniqueTags = [...new Set([...sample.tags, ...newTags])];
      sample.tags = uniqueTags;
      await sample.save();

      return sample;
    } catch (error) {
      logger.error(`Failed to add tags: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Remove tags from a sample
   */
  static async removeTags(sampleId, tags) {
    try {
      const sample = await MalwareSample.findById(sampleId);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      const tagsToRemove = Array.isArray(tags) ? tags : [tags];
      sample.tags = sample.tags.filter(t => !tagsToRemove.includes(t));
      await sample.save();

      return sample;
    } catch (error) {
      logger.error(`Failed to remove tags: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Add note to a sample
   */
  static async addNote(sampleId, note) {
    try {
      const sample = await MalwareSample.findById(sampleId);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      sample.notes = sample.notes ? `${sample.notes}\n${note}` : note;
      await sample.save();

      return sample;
    } catch (error) {
      logger.error(`Failed to add note: ${error.message}`, { error });
      throw error;
    }
  }
}

module.exports = SampleService;