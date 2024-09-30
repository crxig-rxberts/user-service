const request = require('supertest');
const express = require('express');
const authRoutes = require('../../src/routes/authRoutes');
const authService = require('../../src/services/authService');
const errorHandler = require('../../src/middleware/errorHandler');
const {UnauthorizedError} = require('../../src/middleware/errors');

jest.mock('../../src/services/authService');
jest.mock('../../src/config/cognito', () => ({
  cognitoIdentityServiceProvider: {
    signUp: jest.fn(),
    confirmSignUp: jest.fn(),
    initiateAuth: jest.fn(),
    forgotPassword: jest.fn(),
    getUser: jest.fn(),
  },
  jwtVerifier: {
    verify: jest.fn(),
  },
  CognitoJwtVerifier: {
    create: jest.fn().mockReturnValue({
      verify: jest.fn(),
    }),
  },
  userPoolId: 'mock-user-pool-id',
  clientId: 'mock-client-id',
  clientSecret: 'mock-client-secret',
}));
jest.mock('../../src/utils/logger');

const app = express();
app.use(express.json());
app.use('/auth', authRoutes);
app.use(errorHandler);

describe('Auth API Integration Tests', () => {
  const mockUser = {
    username: 'testuser',
    password: 'Test@123',
    email: 'test@example.com',
    userType: 'CLIENT'
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /auth/register', () => {
    it('should register a new user', async () => {
      authService.register.mockResolvedValue({ UserSub: 'test-user-sub' });

      const response = await request(app)
        .post('/auth/register')
        .send(mockUser)
        .expect(201);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('User registered successfully');
      expect(authService.register).toHaveBeenCalledWith(
        mockUser.username,
        mockUser.password,
        mockUser.email,
        mockUser.userType
      );
    });

    it('should return 400 for invalid input', async () => {
      const invalidUser = { ...mockUser, userType: 'INVALID_TYPE' };

      const response = await request(app)
        .post('/auth/register')
        .send(invalidUser)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('"userType" must be one of [CLIENT, SERVICE_PROVIDER]');
    });
  });

  describe('POST /auth/confirm-registration', () => {
    it('should confirm user registration', async () => {
      authService.confirmRegistration.mockResolvedValue();

      const response = await request(app)
        .post('/auth/confirm-registration')
        .send({ username: mockUser.username, confirmationCode: '123456' })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Registration confirmed successfully');
      expect(authService.confirmRegistration).toHaveBeenCalledWith(mockUser.username, '123456');
    });
  });

  describe('POST /auth/login', () => {
    it('should login a user', async () => {
      const mockAuthResult = {
        AccessToken: 'mock-access-token',
        RefreshToken: 'mock-refresh-token',
        IdToken: 'mock-id-token',
        userAttributes: {
          username: mockUser.username,
          userType: mockUser.userType
        }
      };
      authService.login.mockResolvedValue(mockAuthResult);

      const response = await request(app)
        .post('/auth/login')
        .send({ username: mockUser.username, password: mockUser.password })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Login successful');
      expect(response.body.data).toEqual(mockAuthResult);
      expect(authService.login).toHaveBeenCalledWith(mockUser.username, mockUser.password);
    });
  });

  describe('POST /auth/forgot-password', () => {
    it('should initiate forgot password process', async () => {
      authService.forgotPassword.mockResolvedValue();

      const response = await request(app)
        .post('/auth/forgot-password')
        .send({ username: mockUser.username })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Password reset initiated');
      expect(authService.forgotPassword).toHaveBeenCalledWith(mockUser.username);
    });
  });

  describe('POST /auth/refresh-token', () => {
    it('should refresh the token', async () => {
      const mockRefreshResult = {
        AuthenticationResult: {
          AccessToken: 'new-access-token',
          IdToken: 'new-id-token'
        },
        userAttributes: {
          username: mockUser.username,
          userType: mockUser.userType
        }
      };
      authService.refreshToken.mockResolvedValue(mockRefreshResult);

      const response = await request(app)
        .post('/auth/refresh-token')
        .send({ refreshToken: 'mock-refresh-token', sub: 'mock-sub' })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Token refreshed successfully');
      expect(response.body.data).toEqual(mockRefreshResult);
      expect(authService.refreshToken).toHaveBeenCalledWith('mock-refresh-token', 'mock-sub');
    });
  });

  describe('GET /auth/verify-token', () => {
    it('should verify the token', async () => {
      const mockPayload = { sub: 'user123', username: 'testuser' };
      authService.verifyAccessToken.mockResolvedValue(mockPayload);

      const response = await request(app)
        .get('/auth/verify-token')
        .set('Authorization', 'Bearer mock-access-token')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Access token is valid');
      expect(response.body.data).toEqual(mockPayload);
      expect(authService.verifyAccessToken).toHaveBeenCalledWith('mock-access-token');
    });

    it('should handle invalid token', async () => {
      authService.verifyAccessToken.mockRejectedValue(new UnauthorizedError('Invalid access token'));

      const response = await request(app)
        .get('/auth/verify-token')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid access token');
    });
  });
});
