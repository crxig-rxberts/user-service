const authController = require('../../../src/controllers/authController');
const authService = require('../../../src/services/authService');
const { formatResponse } = require('../../../src/utils/formatResponse');

jest.mock('../../../src/config/cognito', () => ({
  cognitoIdentityServiceProvider: {},
  userPoolId: 'mock-user-pool-id',
  clientId: 'mock-client-id',
  clientSecret: 'mock-client-secret',
  jwtVerifier: {
    verify: jest.fn(),
  },
}));

jest.mock('../../../src/services/authService');
jest.mock('../../../src/utils/formatResponse');

describe('AuthController', () => {
  let mockRequest;
  let mockResponse;
  let mockNext;

  beforeEach(() => {
    mockRequest = {
      body: {},
      headers: {}
    };
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    mockNext = jest.fn();
    jest.clearAllMocks();
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      mockRequest.body = {
        username: 'testuser',
        password: 'password123',
        email: 'test@example.com',
        userType: 'CLIENT'
      };
      const mockResult = { userId: '123' };
      authService.register.mockResolvedValue(mockResult);
      formatResponse.mockReturnValue({ success: true, message: 'User registered successfully', data: mockResult });

      await authController.register(mockRequest, mockResponse, mockNext);

      expect(authService.register).toHaveBeenCalledWith('testuser', 'password123', 'test@example.com', 'CLIENT');
      expect(mockResponse.status).toHaveBeenCalledWith(201);
      expect(mockResponse.json).toHaveBeenCalledWith({ success: true, message: 'User registered successfully', data: mockResult });
    });

    it('should handle registration errors', async () => {
      mockRequest.body = {
        username: 'testuser',
        password: 'password123',
        email: 'test@example.com',
        userType: 'CLIENT'
      };
      const mockError = new Error('Registration failed');
      authService.register.mockRejectedValue(mockError);

      await authController.register(mockRequest, mockResponse, mockNext);

      expect(mockNext).toHaveBeenCalledWith(mockError);
    });
  });

  describe('confirmRegistration', () => {
    it('should confirm registration successfully', async () => {
      mockRequest.body = {
        username: 'testuser',
        confirmationCode: '123456'
      };
      authService.confirmRegistration.mockResolvedValue();
      formatResponse.mockReturnValue({ success: true, message: 'Registration confirmed successfully' });

      await authController.confirmRegistration(mockRequest, mockResponse, mockNext);

      expect(authService.confirmRegistration).toHaveBeenCalledWith('testuser', '123456');
      expect(mockResponse.json).toHaveBeenCalledWith({ success: true, message: 'Registration confirmed successfully' });
    });

    it('should handle confirmation errors', async () => {
      mockRequest.body = {
        username: 'testuser',
        confirmationCode: '123456'
      };
      const mockError = new Error('Confirmation failed');
      authService.confirmRegistration.mockRejectedValue(mockError);

      await authController.confirmRegistration(mockRequest, mockResponse, mockNext);

      expect(mockNext).toHaveBeenCalledWith(mockError);
    });
  });

  describe('login', () => {
    it('should login user successfully', async () => {
      mockRequest.body = {
        username: 'testuser',
        password: 'password123'
      };
      const mockResult = { token: 'abc123' };
      authService.login.mockResolvedValue(mockResult);
      formatResponse.mockReturnValue({ success: true, message: 'Login successful', data: mockResult });

      await authController.login(mockRequest, mockResponse, mockNext);

      expect(authService.login).toHaveBeenCalledWith('testuser', 'password123');
      expect(mockResponse.json).toHaveBeenCalledWith({ success: true, message: 'Login successful', data: mockResult });
    });

    it('should handle login errors', async () => {
      mockRequest.body = {
        username: 'testuser',
        password: 'password123'
      };
      const mockError = new Error('Login failed');
      authService.login.mockRejectedValue(mockError);

      await authController.login(mockRequest, mockResponse, mockNext);

      expect(mockNext).toHaveBeenCalledWith(mockError);
    });
  });

});
