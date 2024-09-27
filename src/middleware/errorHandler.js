const logger = require('../utils/logger');
const { formatResponse } = require('../utils/formatResponse');
const {
  AuthError,
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError
} = require('./errors');

function errorHandler(err, req, res, next) {
  const errorTypes = [
    ValidationError,
    UnauthorizedError,
    ForbiddenError,
    NotFoundError,
    ConflictError,
    AuthError
  ];

  for (const ErrorType of errorTypes) {
    if (err instanceof ErrorType) {
      logger.error('Known error caught by middleware', {
        errorType: ErrorType.name,
        message: err.message,
        stack: err.stack
      });
      return res.status(err.statusCode).json(formatResponse(err.message, null, false));
    }
  }

  logger.error('Unknown error caught by middleware', {
    error: err.message,
    stack: err.stack
  });

  // In production, don't send detailed error messages to the client
  const message = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message;

  res.status(500).json(formatResponse(message, null, false));
}

module.exports = errorHandler;
