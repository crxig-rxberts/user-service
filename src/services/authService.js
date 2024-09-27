const { cognitoIdentityServiceProvider, clientId, clientSecret } = require('../config/cognito');
const crypto = require('crypto');
const logger = require('../utils/logger');
const {
  ValidationError,
  UnauthorizedError,
  NotFoundError,
  ConflictError,
  AuthError,
} = require('../middleware/errors');

class AuthService {
  calculateHash(username) {
    return crypto.createHmac('SHA256', clientSecret)
      .update(username + clientId)
      .digest('base64');
  }

  async register(username, password, email, userType = {}) {
    if (!['CLIENT', 'SERVICE_PROVIDER'].includes(userType)) {
      throw new ValidationError('Invalid user type');
    }

    const userAttributes = [
      { Name: 'email', Value: email },
      { Name: 'custom:userType', Value: userType }
    ];

    const params = {
      ClientId: clientId,
      Password: password,
      Username: username,
      UserAttributes: userAttributes,
      SecretHash: this.calculateHash(username)
    };

    try {
      const data = await cognitoIdentityServiceProvider.signUp(params).promise();
      logger.info('User registered successfully', { username: username, userType });
      return data;
    } catch (error) {
      logger.error('Error registering user', { error, username: username, userType });
      if (error.code === 'UsernameExistsException') {
        throw new ConflictError('Username already exists');
      } else if (error.code === 'InvalidParameterException') {
        throw new ValidationError(error.message);
      }
      throw new AuthError(error.message, 500);
    }
  }

  async confirmRegistration(username, confirmationCode) {
    const params = {
      ClientId: clientId,
      ConfirmationCode: confirmationCode,
      Username: username,
      SecretHash: this.calculateHash(username),
    };

    try {
      await cognitoIdentityServiceProvider.confirmSignUp(params).promise();
      logger.info('User registration confirmed', { username });
    } catch (error) {
      logger.error('Error confirming user registration', { error, username });
      if (error.code === 'CodeMismatchException') {
        throw new ValidationError('Invalid confirmation code');
      }
      if (error.code === 'ExpiredCodeException') {
        throw new ValidationError('Confirmation code has expired');
      }
      throw new AuthError(error.message, 500);
    }
  }

  async login(email, password) {
    const params = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: clientId,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
        SECRET_HASH: this.calculateHash(email)
      },
    };

    try {
      const data = await cognitoIdentityServiceProvider.initiateAuth(params).promise();
      const authResult = data.AuthenticationResult;
      const userAttributes = await this.getUserAttributes(authResult.AccessToken);

      logger.info('User logged in successfully', { username: userAttributes.username });

      return {
        userAttributes: userAttributes,
        ...authResult
      };
    } catch (error) {
      logger.error('Error logging in user', { error });
      if (error.code === 'NotAuthorizedException') {
        throw new UnauthorizedError('Invalid username or password');
      }
      if (error.code === 'UserNotFoundException') {
        throw new NotFoundError('User not found');
      }
      throw new AuthError(error.message, 500);
    }
  }

  async forgotPassword(username) {
    const params = {
      ClientId: clientId,
      Username: username,
      SecretHash: this.calculateHash(username)
    };

    try {
      await cognitoIdentityServiceProvider.forgotPassword(params).promise();
    } catch (error) {
      logger.error('Error initiating password reset', { error });
      if (error.code === 'UserNotFoundException') {
        throw new NotFoundError('User not found');
      }
      throw new AuthError(error.message, 500);
    }
  }

  async refreshToken(refreshToken, sub) {
    const params = {
      AuthFlow: 'REFRESH_TOKEN_AUTH',
      ClientId: clientId,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
        SECRET_HASH: this.calculateHash(sub)
      }
    };

    try {
      const { AuthenticationResult } = await cognitoIdentityServiceProvider.initiateAuth(params).promise();
      logger.info('Token refreshed successfully');
      const userAttributes = await this.getUserAttributes(AuthenticationResult.AccessToken);
      return {
        AuthenticationResult,
        userAttributes,
      };
    } catch (error) {
      logger.error('Error refreshing token', { error });
      if (error.code === 'NotAuthorizedException') {
        throw new UnauthorizedError('Invalid refresh token');
      }
      throw new AuthError(error.message, 500);
    }
  }

  async verifyAccessToken(accessToken) {
    const params = {
      AccessToken: accessToken
    };

    try {
      await cognitoIdentityServiceProvider.getUser(params).promise();
      logger.info('Access token verified successfully');
      return true;
    } catch (error) {
      logger.error('Error verifying access token');
      if (error.code === 'NotAuthorizedException') {
        throw new UnauthorizedError('Invalid access token');
      }
      throw new AuthError(error.message, 500);
    }
  }

  async getUserAttributes(accessToken) {
    const params = {
      AccessToken: accessToken
    };

    try {
      const data = await cognitoIdentityServiceProvider.getUser(params).promise();
      const userType = data.UserAttributes.find(attr => attr.Name === 'custom:userType');

      return {
        userType: userType ? userType.Value : null,
        username: data.Username,
      };
    } catch (error) {
      logger.error('Error getting user attributes', { error });
      if (error.code === 'NotAuthorizedException') {
        throw new UnauthorizedError('Invalid access token');
      }
      throw new AuthError(error.message, 500);
    }
  }
}

module.exports = new AuthService();
