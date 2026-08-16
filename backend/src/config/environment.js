const dotenv = require('dotenv');

dotenv.config();

const environment = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT, 10) || 5000,
  mongoUri: process.env.MONGODB_URI || 'mongodb://localhost:27017/malscope',
  jwtSecret: process.env.JWT_SECRET || 'dev-secret-change-me',
  vtApiKey: process.env.VT_API_KEY || '',
  vm: {
    name: process.env.VM_NAME || 'MalScope-Windows-Lab',
    snapshot: process.env.VM_SNAPSHOT || 'MalScope-Clean',
    user: process.env.VM_USER || 'admin',
    password: process.env.VM_PASSWORD || 'password',
  },
};

module.exports = environment;