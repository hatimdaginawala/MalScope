const SampleService = require('../services/sampleService');
const AnalysisService = require('../services/analysisService');
const logger = require('../utils/logger');
const { ApiError } = require('../middleware/errorMiddleware');

class SampleController {
  /**
   * Upload a new sample
   * POST /api/v1/samples
   */
  static async upload(req, res, next) {
    try {
      if (!req.file) {
        throw new ApiError(400, 'No file uploaded');
      }

      const userId = req.user ? req.user.id : null;
      const { filename } = req.file;
      const fileBuffer = req.file.buffer;

      const result = await SampleService.uploadSample(fileBuffer, filename, userId);

      if (result.duplicate) {
        return res.status(409).json({
          success: true,
          message: 'Sample already exists in the system',
          data: {
            sample: result.sample,
            duplicate: true,
          },
        });
      }

      logger.info(`Sample uploaded: ${result.sample.sha256} by user ${userId || 'anonymous'}`);

      res.status(201).json({
        success: true,
        message: 'Sample uploaded successfully',
        data: {
          sample: result.sample,
          analysis: result.analysis,
          hashes: result.hashes,
          duplicate: false,
        },
      });
    } catch (error) {
      logger.error(`Upload failed: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get all samples
   * GET /api/v1/samples
   */
  static async getSamples(req, res, next) {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 20;
      const filters = {
        status: req.query.status,
        fileType: req.query.fileType,
        search: req.query.search,
      };

      const result = await SampleService.getSamples(page, limit, filters);

      res.status(200).json({
        success: true,
        data: result.samples,
        pagination: result.pagination,
      });
    } catch (error) {
      logger.error(`Failed to get samples: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get sample by ID
   * GET /api/v1/samples/:id
   */
  static async getSample(req, res, next) {
    try {
      const { id } = req.params;

      const sample = await SampleService.getSampleById(id);

      // Get related analyses
      const analyses = await AnalysisService.getAnalysesForSample(id);

      res.status(200).json({
        success: true,
        data: {
          sample,
          analyses: analyses.analyses,
          analysisCount: analyses.pagination.total,
        },
      });
    } catch (error) {
      logger.error(`Failed to get sample: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get sample by hash
   * GET /api/v1/samples/hash/:hash
   */
  static async getSampleByHash(req, res, next) {
    try {
      const { hash } = req.params;

      const sample = await SampleService.getSampleByHash(hash);

      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      res.status(200).json({
        success: true,
        data: sample,
      });
    } catch (error) {
      logger.error(`Failed to get sample by hash: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Delete sample
   * DELETE /api/v1/samples/:id
   */
  static async deleteSample(req, res, next) {
    try {
      const { id } = req.params;

      const result = await SampleService.deleteSample(id);

      res.status(200).json({
        success: true,
        message: result.message,
      });
    } catch (error) {
      logger.error(`Failed to delete sample: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Update sample status
   * PATCH /api/v1/samples/:id/status
   */
  static async updateStatus(req, res, next) {
    try {
      const { id } = req.params;
      const { status } = req.body;

      const sample = await SampleService.updateStatus(id, status);

      res.status(200).json({
        success: true,
        message: 'Sample status updated successfully',
        data: sample,
      });
    } catch (error) {
      logger.error(`Failed to update sample status: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get sample statistics
   * GET /api/v1/samples/stats
   */
  static async getStats(req, res, next) {
    try {
      const MalwareSample = require('../models/MalwareSample');

      const [total, byStatus, byType] = await Promise.all([
        MalwareSample.countDocuments(),
        MalwareSample.aggregate([
          { $group: { _id: '$status', count: { $sum: 1 } } },
        ]),
        MalwareSample.aggregate([
          { $group: { _id: '$fileType', count: { $sum: 1 } } },
        ]),
      ]);

      res.status(200).json({
        success: true,
        data: {
          total,
          byStatus: byStatus.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
          byType: byType.reduce((acc, item) => ({ ...acc, [item._id]: item.count }), {}),
        },
      });
    } catch (error) {
      logger.error(`Failed to get sample stats: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Download sample file
   * GET /api/v1/samples/:id/download
   */
  static async downloadSample(req, res, next) {
    try {
      const { id } = req.params;
      const fs = require('fs');

      const sample = await SampleService.getSampleById(id);
      if (!sample) {
        throw new ApiError(404, 'Sample not found');
      }

      // Check if file exists
      if (!fs.existsSync(sample.storagePath)) {
        throw new ApiError(404, 'Sample file not found on disk');
      }

      res.download(sample.storagePath, sample.filename);
    } catch (error) {
      logger.error(`Failed to download sample: ${error.message}`, { error });
      next(error);
    }
  }
}

module.exports = SampleController;