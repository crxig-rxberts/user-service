const errorHandler = require('../../../src/middleware/errorHandler');
const { formatResponse } = require('../../../src/utils/formatResponse');
const {
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError
} = require('../../../src/middleware/errors');

jest.mock('../../../src/utils/logger', () => ({
  error: jest.fn()
}));

describe('errorHandler middleware', () => {
  let mockRequest;
  let mockResponse;
  let nextFunction;

  beforeEach(() => {
    mockRequest = {};
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    nextFunction = jest.fn();
  });

  it('should handle ValidationError', () => {
    const error = new ValidationError('Validation failed');
    errorHandler(error, mockRequest, mockResponse, nextFunction);
    expect(mockResponse.status).toHaveBeenCalledWith(400);
    expect(mockResponse.json).toHaveBeenCalledWith(formatResponse('Validation failed', null, false));
  });

  it('should handle UnauthorizedError', () => {
    const error = new UnauthorizedError('Unauthorized');
    errorHandler(error, mockRequest, mockResponse, nextFunction);
    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith(formatResponse('Unauthorized', null, false));
  });

  it('should handle ForbiddenError', () => {
    const error = new ForbiddenError('Forbidden');
    errorHandler(error, mockRequest, mockResponse, nextFunction);
    expect(mockResponse.status).toHaveBeenCalledWith(403);
    expect(mockResponse.json).toHaveBeenCalledWith(formatResponse('Forbidden', null, false));
  });

  it('should handle NotFoundError', () => {
    const error = new NotFoundError('Not Found');
    errorHandler(error, mockRequest, mockResponse, nextFunction);
    expect(mockResponse.status).toHaveBeenCalledWith(404);
    expect(mockResponse.json).toHaveBeenCalledWith(formatResponse('Not Found', null, false));
  });

  it('should handle ConflictError', () => {
    const error = new ConflictError('Conflict');
    errorHandler(error, mockRequest, mockResponse, nextFunction);
    expect(mockResponse.status).toHaveBeenCalledWith(409);
    expect(mockResponse.json).toHaveBeenCalledWith(formatResponse('Conflict', null, false));
  });

  it('should handle unknown errors', () => {
    const error = new Error('Unknown Error');
    errorHandler(error, mockRequest, mockResponse, nextFunction);
    expect(mockResponse.status).toHaveBeenCalledWith(500);
    expect(mockResponse.json).toHaveBeenCalledWith(formatResponse('Unknown Error', null, false));
  });
});
