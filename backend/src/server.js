const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const environment = require('./config/environment');
const { connectDB } = require('./config/database');
const logger = require('./utils/logger');
const { errorHandler, notFoundHandler } = require('./middleware/errorMiddleware');

// Initialize Express
const app = express();

// Security middleware
app.use(helmet());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
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

// Additional API routes will be added here in later phases

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// Start server
const startServer = async () => {
  try {
    // Connect to MongoDB
    await connectDB();

    app.listen(environment.port, () => {
      logger.info(`🚀 MalScope backend running on port ${environment.port}`);
      logger.info(`📊 Health: http://localhost:${environment.port}/api/health`);
      logger.info(`🌍 Environment: ${environment.nodeEnv}`);
    });
  } catch (error) {
    logger.error(`Failed to start server: ${error.message}`);
    process.exit(1);
  }
};

// Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', { promise, reason });
  // Don't exit - keep the process running for now
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', { error: error.message, stack: error.stack });
  // Exit on uncaught exception
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

// Start the server (only if not in test mode)
if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };