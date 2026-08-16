const mongoose = require('mongoose');
const logger = require('../utils/logger');
const environment = require('./environment');

const connectDB = async () => {
  try {
    await mongoose.connect(environment.mongoUri, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    logger.info(`MongoDB connected: ${environment.mongoUri}`);
    return mongoose.connection;
  } catch (error) {
    logger.error(`MongoDB connection error: ${error.message}`);
    throw error;
  }
};

const disconnectDB = async () => {
  await mongoose.disconnect();
  logger.info('MongoDB disconnected');
};

module.exports = { connectDB, disconnectDB };