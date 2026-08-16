// ===== CLEAR MONGOOSE MODEL CACHE - MUST BE FIRST =====
const mongoose = require('mongoose');
mongoose.models = {};
mongoose.modelSchemas = {};
// ======================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const environment = require('./config/environment');
const { connectDB } = require('./config/database');
const logger = require('./utils/logger');
const { errorHandler, notFoundHandler } = require('./middleware/errorMiddleware');

// Import routes
const authRoutes = require('./routes/authRoutes');
const sampleRoutes = require('./routes/sampleRoutes');
const analysisRoutes = require('./routes/analysisRoutes');
const staticAnalysisRoutes = require('./routes/staticAnalysisRoutes');
const dynamicAnalysisRoutes = require('./routes/dynamicAnalysisRoutes');
const threatIntelRoutes = require('./routes/threatIntelRoutes');
const reportRoutes = require('./routes/reportRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');

// Initialize Express
const app = express();

// Security middleware
app.use(helmet());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP',
});
app.use('/api', limiter);

// Body parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Health endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'MalScope',
    timestamp: new Date().toISOString(),
    environment: environment.nodeEnv,
  });
});

// API Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/samples', sampleRoutes);
app.use('/api/v1/analyses', analysisRoutes);
app.use('/api/v1/analyses', staticAnalysisRoutes);
app.use('/api/v1/analyses', dynamicAnalysisRoutes);
app.use('/api/v1/threat-intel', threatIntelRoutes);
app.use('/api/v1/reports', reportRoutes);
app.use('/api/v1/dashboard', dashboardRoutes);

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// Start server
const startServer = async () => {
  try {
    await connectDB();

    app.listen(environment.port, () => {
      logger.info(`🚀 MalScope backend running on port ${environment.port}`);
      logger.info(`📊 Health: http://localhost:${environment.port}/api/health`);
      logger.info(`🌍 Environment: ${environment.nodeEnv}`);
      logger.info(`🔐 Auth: http://localhost:${environment.port}/api/v1/auth`);
      logger.info(`📁 Samples: http://localhost:${environment.port}/api/v1/samples`);
      logger.info(`🔬 Analyses: http://localhost:${environment.port}/api/v1/analyses`);
    });
  } catch (error) {
    logger.error(`Failed to start server: ${error.message}`);
    process.exit(1);
  }
};

// Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', { promise, reason });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', { error: error.message, stack: error.stack });
  process.exit(1);
});

// Graceful shutdown
const shutdown = async () => {
  logger.info('Shutting down gracefully...');
  await mongoose.disconnect();
  process.exit(0);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };