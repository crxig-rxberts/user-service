const express = require('express');
const authController = require('../controllers/authController');
const validateRequest = require('../utils/validateRequest');
const authSchemas = require('../schemas/authSchemas');

const router = express.Router();

router.post('/register', validateRequest(authSchemas.register), authController.register);
router.post('/confirm-registration', validateRequest(authSchemas.confirmRegistration), authController.confirmRegistration);
router.post('/login', validateRequest(authSchemas.login), authController.login);
router.post('/forgot-password', validateRequest(authSchemas.forgotPassword), authController.forgotPassword);
router.post('/refresh-token', validateRequest(authSchemas.refreshToken), authController.refreshToken);
router.get('/verify-token', authController.verifyToken);

module.exports = router;
