const AuthService = require('../../../src/services/authService');
const { cognitoIdentityServiceProvider, jwtVerifier  } = require('../../../src/config/cognito');
const {
  ValidationError,
  UnauthorizedError,
  NotFoundError,
  ConflictError,
  AuthError,
} = require('../../../src/middleware/errors');

jest.mock('../../../src/config/cognito');
jest.mock('../../../src/utils/logger');
jest.mock('../../../src/config/cognito', () => ({
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
  userPoolId: 'mock-user-pool-id',
  clientId: 'mock-client-id',
  clientSecret: 'mock-client-secret',
}));

describe('AuthService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetAllMocks();
    jest.spyOn(AuthService, 'calculateHash').mockReturnValue('mocked-hash');
    cognitoIdentityServiceProvider.getUser.mockReset();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('getUserAttributes', () => {
    it('should get user attributes successfully', async () => {
      const mockGetUser = jest.fn().mockResolvedValue({
        Username: 'testuser',
        UserAttributes: [
          { Name: 'custom:userType', Value: 'CLIENT' }
        ]
      });
      cognitoIdentityServiceProvider.getUser.mockImplementation(() => ({
        promise: mockGetUser
      }));

      const result = await AuthService.getUserAttributes('validAccessToken');

      expect(result).toEqual({
        userType: 'CLIENT',
        username: 'testuser'
      });
      expect(mockGetUser).toHaveBeenCalled();
    });

    it('should return null userType if not found in attributes', async () => {
      const mockGetUser = jest.fn().mockResolvedValue({
        Username: 'testuser',
        UserAttributes: []
      });
      cognitoIdentityServiceProvider.getUser.mockImplementation(() => ({
        promise: mockGetUser
      }));

      const result = await AuthService.getUserAttributes('validAccessToken');

      expect(result).toEqual({
        userType: null,
        username: 'testuser'
      });
    });

    it('should throw UnauthorizedError for invalid access token', async () => {
      const mockGetUser = jest.fn().mockRejectedValue({ code: 'NotAuthorizedException' });
      cognitoIdentityServiceProvider.getUser.mockImplementation(() => ({
        promise: mockGetUser
      }));

      await expect(AuthService.getUserAttributes('invalidAccessToken'))
        .rejects.toThrow(UnauthorizedError);
    });

    it('should throw AuthError for other errors', async () => {
      const mockGetUser = jest.fn().mockRejectedValue(new Error('Unknown error'));
      cognitoIdentityServiceProvider.getUser.mockImplementation(() => ({
        promise: mockGetUser
      }));

      await expect(AuthService.getUserAttributes('validAccessToken'))
        .rejects.toThrow(AuthError);
    });
  });

  // Other tests for different methods
  describe('register', () => {
    it('should register a new user successfully', async () => {
      const mockSignUp = jest.fn().mockResolvedValue({ UserSub: 'testUserId' });
      cognitoIdentityServiceProvider.signUp.mockReturnValue({ promise: mockSignUp });

      const result = await AuthService.register('testuser', 'password123', 'test@example.com', 'CLIENT');

      expect(result).toEqual({ UserSub: 'testUserId' });
      expect(mockSignUp).toHaveBeenCalled();
    });

    it('should throw ValidationError for invalid user type', async () => {
      await expect(AuthService.register('testuser', 'password123', 'test@example.com', 'INVALID'))
        .rejects.toThrow(ValidationError);
    });

    it('should throw ConflictError if username already exists', async () => {
      const mockSignUp = jest.fn().mockRejectedValue({ code: 'UsernameExistsException' });
      cognitoIdentityServiceProvider.signUp.mockReturnValue({ promise: mockSignUp });

      await expect(AuthService.register('existinguser', 'password123', 'test@example.com', 'CLIENT'))
        .rejects.toThrow(ConflictError);
    });

    it('should throw ValidationError for invalid parameters', async () => {
      const mockSignUp = jest.fn().mockRejectedValue({ code: 'InvalidParameterException' });
      cognitoIdentityServiceProvider.signUp.mockReturnValue({ promise: mockSignUp });

      await expect(AuthService.register('testuser', 'weak', 'test@example.com', 'CLIENT'))
        .rejects.toThrow(ValidationError);
    });

    it('should throw AuthError for other errors', async () => {
      const mockSignUp = jest.fn().mockRejectedValue(new Error('Unknown error'));
      cognitoIdentityServiceProvider.signUp.mockReturnValue({ promise: mockSignUp });

      await expect(AuthService.register('testuser', 'password123', 'test@example.com', 'CLIENT'))
        .rejects.toThrow(AuthError);
    });
  });

  describe('confirmRegistration', () => {
    it('should confirm registration successfully', async () => {
      const mockConfirmSignUp = jest.fn().mockResolvedValue({});
      cognitoIdentityServiceProvider.confirmSignUp.mockReturnValue({ promise: mockConfirmSignUp });

      await AuthService.confirmRegistration('testuser', '123456');

      expect(mockConfirmSignUp).toHaveBeenCalled();
    });

    it('should throw ValidationError for invalid confirmation code', async () => {
      const mockConfirmSignUp = jest.fn().mockRejectedValue({ code: 'CodeMismatchException' });
      cognitoIdentityServiceProvider.confirmSignUp.mockReturnValue({ promise: mockConfirmSignUp });

      await expect(AuthService.confirmRegistration('testuser', 'invalid'))
        .rejects.toThrow(ValidationError);
    });

    it('should throw ValidationError for expired confirmation code', async () => {
      const mockConfirmSignUp = jest.fn().mockRejectedValue({ code: 'ExpiredCodeException' });
      cognitoIdentityServiceProvider.confirmSignUp.mockReturnValue({ promise: mockConfirmSignUp });

      await expect(AuthService.confirmRegistration('testuser', 'expired'))
        .rejects.toThrow(ValidationError);
    });

    it('should throw AuthError for other errors', async () => {
      const mockConfirmSignUp = jest.fn().mockRejectedValue(new Error('Unknown error'));
      cognitoIdentityServiceProvider.confirmSignUp.mockReturnValue({ promise: mockConfirmSignUp });

      await expect(AuthService.confirmRegistration('testuser', '123456'))
        .rejects.toThrow(AuthError);
    });
  });

  describe('login', () => {
    it('should login user successfully', async () => {
      const mockInitiateAuth = jest.fn().mockResolvedValue({
        AuthenticationResult: { AccessToken: 'mockAccessToken' }
      });
      cognitoIdentityServiceProvider.initiateAuth.mockReturnValue({ promise: mockInitiateAuth });

      AuthService.getUserAttributes = jest.fn().mockResolvedValue({
        userType: 'CLIENT',
        username: 'testuser'
      });

      const result = await AuthService.login('testuser', 'password123');

      expect(result).toHaveProperty('userAttributes');
      expect(result).toHaveProperty('AccessToken');
      expect(mockInitiateAuth).toHaveBeenCalled();
    });

    it('should throw UnauthorizedError for invalid credentials', async () => {
      const mockInitiateAuth = jest.fn().mockRejectedValue({ code: 'NotAuthorizedException' });
      cognitoIdentityServiceProvider.initiateAuth.mockReturnValue({ promise: mockInitiateAuth });

      await expect(AuthService.login('testuser', 'wrongpassword'))
        .rejects.toThrow(UnauthorizedError);
    });

    it('should throw NotFoundError for non-existent user', async () => {
      const mockInitiateAuth = jest.fn().mockRejectedValue({ code: 'UserNotFoundException' });
      cognitoIdentityServiceProvider.initiateAuth.mockReturnValue({ promise: mockInitiateAuth });

      await expect(AuthService.login('nonexistentuser', 'password123'))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw AuthError for other errors', async () => {
      const mockInitiateAuth = jest.fn().mockRejectedValue(new Error('Unknown error'));
      cognitoIdentityServiceProvider.initiateAuth.mockReturnValue({ promise: mockInitiateAuth });

      await expect(AuthService.login('testuser', 'password123'))
        .rejects.toThrow(AuthError);
    });
  });

  describe('forgotPassword', () => {
    it('should initiate forgot password process successfully', async () => {
      const mockForgotPassword = jest.fn().mockResolvedValue({});
      cognitoIdentityServiceProvider.forgotPassword.mockReturnValue({ promise: mockForgotPassword });

      await AuthService.forgotPassword('testuser');

      expect(mockForgotPassword).toHaveBeenCalled();
    });

    it('should throw NotFoundError for non-existent user', async () => {
      const mockForgotPassword = jest.fn().mockRejectedValue({ code: 'UserNotFoundException' });
      cognitoIdentityServiceProvider.forgotPassword.mockReturnValue({ promise: mockForgotPassword });

      await expect(AuthService.forgotPassword('nonexistentuser'))
        .rejects.toThrow(NotFoundError);
    });

    it('should throw AuthError for other errors', async () => {
      const mockForgotPassword = jest.fn().mockRejectedValue(new Error('Unknown error'));
      cognitoIdentityServiceProvider.forgotPassword.mockReturnValue({ promise: mockForgotPassword });

      await expect(AuthService.forgotPassword('testuser'))
        .rejects.toThrow(AuthError);
    });
  });
  describe('refreshToken', () => {
    it('should refresh token successfully', async () => {
      const mockInitiateAuth = jest.fn().mockResolvedValue({
        AuthenticationResult: { AccessToken: 'newAccessToken' }
      });
      cognitoIdentityServiceProvider.initiateAuth.mockReturnValue({ promise: mockInitiateAuth });

      AuthService.getUserAttributes = jest.fn().mockResolvedValue({
        userType: 'CLIENT',
        username: 'testuser'
      });

      const result = await AuthService.refreshToken('validRefreshToken', 'testuser');

      expect(result).toHaveProperty('AuthenticationResult');
      expect(result).toHaveProperty('userAttributes');
      expect(mockInitiateAuth).toHaveBeenCalled();
      expect(AuthService.getUserAttributes).toHaveBeenCalled();
    });

    it('should throw UnauthorizedError for invalid refresh token', async () => {
      const mockInitiateAuth = jest.fn().mockRejectedValue({ code: 'NotAuthorizedException' });
      cognitoIdentityServiceProvider.initiateAuth.mockReturnValue({ promise: mockInitiateAuth });

      await expect(AuthService.refreshToken('invalidRefreshToken', 'testuser'))
        .rejects.toThrow(UnauthorizedError);
    });

    it('should throw AuthError for other errors', async () => {
      const mockInitiateAuth = jest.fn().mockRejectedValue(new Error('Unknown error'));
      cognitoIdentityServiceProvider.initiateAuth.mockReturnValue({ promise: mockInitiateAuth });

      await expect(AuthService.refreshToken('validRefreshToken', 'testuser'))
        .rejects.toThrow(AuthError);
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify access token successfully', async () => {
      const mockPayload = { sub: 'user123', username: 'testuser' };
      jwtVerifier.verify.mockResolvedValue(mockPayload);

      const result = await AuthService.verifyAccessToken('validAccessToken');

      expect(result).toEqual(mockPayload);
      expect(jwtVerifier.verify).toHaveBeenCalledWith('validAccessToken');
    });

    it('should throw UnauthorizedError for expired token', async () => {
      jwtVerifier.verify.mockRejectedValue({ name: 'TokenExpiredError' });

      await expect(AuthService.verifyAccessToken('expiredToken'))
          .rejects.toThrow(UnauthorizedError);
      expect(jwtVerifier.verify).toHaveBeenCalledWith('expiredToken');
    });

    it('should throw UnauthorizedError for invalid token', async () => {
      jwtVerifier.verify.mockRejectedValue({ name: 'JsonWebTokenError' });

      await expect(AuthService.verifyAccessToken('invalidToken'))
          .rejects.toThrow(UnauthorizedError);
      expect(jwtVerifier.verify).toHaveBeenCalledWith('invalidToken');
    });

    it('should throw AuthError for other errors', async () => {
      jwtVerifier.verify.mockRejectedValue(new Error('Unknown error'));

      await expect(AuthService.verifyAccessToken('validAccessToken'))
          .rejects.toThrow(AuthError);
      expect(jwtVerifier.verify).toHaveBeenCalledWith('validAccessToken');
    });
  });

});
