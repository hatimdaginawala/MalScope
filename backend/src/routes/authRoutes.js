const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/authController');
const { authenticate } = require('../middleware/authMiddleware');
const { validate } = require('../middleware/validationMiddleware');
const { rateLimitMiddleware } = require('../middleware/rateLimitMiddleware');

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post(
  '/register',
  rateLimitMiddleware({ windowMs: 15 * 60 * 1000, max: 5 }), // 5 per 15 min
  validate('register'),
  AuthController.register
);

/**
 * @route   POST /api/v1/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post(
  '/login',
  rateLimitMiddleware({ windowMs: 15 * 60 * 1000, max: 10 }), // 10 per 15 min
  validate('login'),
  AuthController.login
);

/**
 * @route   POST /api/v1/auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post(
  '/logout',
  authenticate,
  AuthController.logout
);

/**
 * @route   GET /api/v1/auth/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get(
  '/me',
  authenticate,
  AuthController.getMe
);

/**
 * @route   PUT /api/v1/auth/me
 * @desc    Update user profile
 * @access  Private
 */
router.put(
  '/me',
  authenticate,
  validate('updateProfile'),
  AuthController.updateMe
);

/**
 * @route   PUT /api/v1/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.put(
  '/change-password',
  authenticate,
  validate('changePassword'),
  AuthController.changePassword
);

/**
 * @route   POST /api/v1/auth/refresh
 * @desc    Refresh JWT token
 * @access  Private
 */
router.post(
  '/refresh',
  authenticate,
  AuthController.refreshToken
);

module.exports = router;