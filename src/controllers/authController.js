const authService = require('../services/authService');
const { formatResponse } = require('../utils/formatResponse');

class AuthController {
  async register(req, res, next) {
    try {
      const { username, password, email, userType } = req.body;
      const result = await authService.register(username, password, email, userType);
      res.status(201).json(formatResponse('User registered successfully', result));
    } catch (error) {
      next(error);
    }
  }

  async confirmRegistration(req, res, next) {
    try {
      const { username, confirmationCode } = req.body;
      await authService.confirmRegistration(username, confirmationCode);
      res.json(formatResponse('Registration confirmed successfully'));
    } catch (error) {
      next(error);
    }
  }

  async login(req, res, next) {
    try {
      const { username, password } = req.body;
      const result = await authService.login(username, password);
      res.json(formatResponse('Login successful', { ...result }));
    } catch (error) {
      next(error);
    }
  }

  async forgotPassword(req, res, next) {
    try {
      const { username } = req.body;
      await authService.forgotPassword(username);
      res.json(formatResponse('Password reset initiated'));
    } catch (error) {
      next(error);
    }
  }

  async refreshToken(req, res, next) {
    const { refreshToken, sub } = req.body;
    try {
      const authResult = await authService.refreshToken(refreshToken, sub);
      res.json(formatResponse('Token refreshed successfully', authResult));
    } catch (error) {
      next(error);
    }
  }

  async verifyToken(req, res, next) {
    try {
      const accessToken = req.headers.authorization.split(' ')[1];
      const payload = await authService.verifyAccessToken(accessToken);
      res.json(formatResponse('Access token is valid', payload));
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new AuthController();
