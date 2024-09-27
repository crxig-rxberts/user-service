class AuthError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AuthError {
  constructor(message) {
    super(message, 400);
  }
}

class UnauthorizedError extends AuthError {
  constructor(message = 'Unauthorized') {
    super(message, 401);
  }
}

class ForbiddenError extends AuthError {
  constructor(message = 'Forbidden') {
    super(message, 403);
  }
}

class NotFoundError extends AuthError {
  constructor(message = 'Resource not found') {
    super(message, 404);
  }
}

class ConflictError extends AuthError {
  constructor(message = 'Resource already exists') {
    super(message, 409);
  }
}

module.exports = {
  AuthError,
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError
};
