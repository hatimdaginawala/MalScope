const User = require('../models/User');
const { ApiError } = require('../middleware/errorMiddleware');
const logger = require('../utils/logger');

class UserController {
  /**
   * Get all users (paginated)
   * GET /api/v1/users
   */
  static async listUsers(req, res, next) {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 15;
      const skip = (page - 1) * limit;

      const users = await User.find({})
        .select('-passwordHash')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit);

      const total = await User.countDocuments({});

      res.status(200).json({
        success: true,
        data: users,
        pagination: {
          total,
          page,
          limit,
          pages: Math.ceil(total / limit),
        },
      });
    } catch (error) {
      logger.error(`Failed to list users: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Get single user
   * GET /api/v1/users/:id
   */
  static async getUser(req, res, next) {
    try {
      const user = await User.findById(req.params.id).select('-passwordHash');
      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      res.status(200).json({
        success: true,
        data: user,
      });
    } catch (error) {
      logger.error(`Failed to get user: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Update user
   * PUT /api/v1/users/:id
   */
  static async updateUser(req, res, next) {
    try {
      const { role, isActive, email } = req.body;
      const user = await User.findById(req.params.id);

      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      // Prevent removing the last admin
      if (user.role === 'admin' && role && role !== 'admin') {
        const adminCount = await User.countDocuments({ role: 'admin' });
        if (adminCount <= 1) {
          throw new ApiError(400, 'Cannot change role of the last admin');
        }
      }
      if (user.role === 'admin' && isActive === false) {
        const adminCount = await User.countDocuments({ role: 'admin', isActive: true });
        if (adminCount <= 1) {
          throw new ApiError(400, 'Cannot deactivate the last active admin');
        }
      }

      if (email) user.email = email;
      if (role) user.role = role;
      if (isActive !== undefined) user.isActive = isActive;

      await user.save();

      logger.info(`User updated by admin: ${user.username} (${user._id})`);

      res.status(200).json({
        success: true,
        message: 'User updated successfully',
        data: {
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
          isActive: user.isActive,
        },
      });
    } catch (error) {
      logger.error(`Failed to update user: ${error.message}`, { error });
      next(error);
    }
  }

  /**
   * Delete user
   * DELETE /api/v1/users/:id
   */
  static async deleteUser(req, res, next) {
    try {
      const user = await User.findById(req.params.id);
      
      if (!user) {
        throw new ApiError(404, 'User not found');
      }

      // Prevent removing the last admin
      if (user.role === 'admin') {
        const adminCount = await User.countDocuments({ role: 'admin' });
        if (adminCount <= 1) {
          throw new ApiError(400, 'Cannot delete the last admin');
        }
      }

      // Cannot delete self
      if (user._id.toString() === req.user.id) {
        throw new ApiError(400, 'Cannot delete your own account');
      }

      await User.findByIdAndDelete(req.params.id);

      logger.info(`User deleted by admin: ${user.username} (${user._id})`);

      res.status(200).json({
        success: true,
        message: 'User deleted successfully',
      });
    } catch (error) {
      logger.error(`Failed to delete user: ${error.message}`, { error });
      next(error);
    }
  }
}

module.exports = UserController;
