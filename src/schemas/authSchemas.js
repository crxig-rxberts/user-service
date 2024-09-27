const Joi = require('joi');

const passwordValidation = Joi.string()
  .min(8)
  .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/)
  .messages({
    'string.pattern.base': 'Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters',
    'string.min': 'Password must be at least 8 characters long',
    'any.required': 'Password is required'
  });

const authSchemas = {
  register: Joi.object({
    username: Joi.string().required(),
    password: passwordValidation.required(),
    email: Joi.string().email().required(),
    userType: Joi.string().valid('CLIENT', 'SERVICE_PROVIDER').required(),
  }),

  confirmRegistration: Joi.object({
    username: Joi.string().required(),
    confirmationCode: Joi.string().required()
  }),

  login: Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required()
  }),

  forgotPassword: Joi.object({
    username: Joi.string().required()
  }),

  refreshToken: Joi.object({
    refreshToken: Joi.string().required(),
    sub: Joi.string().required()
  })
};

module.exports = authSchemas;
