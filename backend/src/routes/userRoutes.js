const express = require('express');
const router = express.Router();
const UserController = require('../controllers/userController');
const { authenticate, authorize } = require('../middleware/authMiddleware');
const { rateLimitMiddleware } = require('../middleware/rateLimitMiddleware');

// All user routes require authentication and admin role
router.use(authenticate, authorize(['admin']));

/**
 * @route   GET /api/v1/users
 * @desc    Get all users (paginated)
 * @access  Private/Admin
 */
router.get(
  '/',
  UserController.listUsers
);

/**
 * @route   GET /api/v1/users/:id
 * @desc    Get single user
 * @access  Private/Admin
 */
router.get(
  '/:id',
  UserController.getUser
);

/**
 * @route   PUT /api/v1/users/:id
 * @desc    Update user
 * @access  Private/Admin
 */
router.put(
  '/:id',
  UserController.updateUser
);

/**
 * @route   DELETE /api/v1/users/:id
 * @desc    Delete user
 * @access  Private/Admin
 */
router.delete(
  '/:id',
  UserController.deleteUser
);

module.exports = router;
