const authSchemas = require('../../../src/schemas/authSchemas');

describe('Auth Schemas', () => {
  describe('register schema', () => {
    it('should validate a valid CLIENT registration', () => {
      const validClientData = {
        username: 'testuser',
        password: 'Password123!',
        email: 'test@example.com',
        userType: 'CLIENT'
      };
      const { error } = authSchemas.register.validate(validClientData);
      expect(error).toBeUndefined();
    });

    it('should validate a valid SERVICE_PROVIDER registration', () => {
      const validProviderData = {
        username: 'testprovider',
        password: 'Password123!',
        email: 'provider@example.com',
        userType: 'SERVICE_PROVIDER',
      };
      const { error } = authSchemas.register.validate(validProviderData);
      expect(error).toBeUndefined();
    });

    it('should reject invalid data', () => {
      const invalidData = {
        username: 'test',
        password: 'weak',
        email: 'invalid-email',
        userType: 'INVALID'
      };
      const { error } = authSchemas.register.validate(invalidData);
      expect(error).toBeDefined();
    });
  });

  describe('confirmRegistration schema', () => {
    it('should validate valid confirmation data', () => {
      const validData = {
        username: 'testuser',
        confirmationCode: '123456'
      };
      const { error } = authSchemas.confirmRegistration.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject invalid confirmation data', () => {
      const invalidData = {
        username: '',
        confirmationCode: ''
      };
      const { error } = authSchemas.confirmRegistration.validate(invalidData);
      expect(error).toBeDefined();
    });
  });

  describe('login schema', () => {
    it('should validate valid login data', () => {
      const validData = {
        username: 'testuser',
        password: 'password123'
      };
      const { error } = authSchemas.login.validate(validData);
      expect(error).toBeUndefined();
    });

    it('should reject invalid login data', () => {
      const invalidData = {
        username: '',
        password: ''
      };
      const { error } = authSchemas.login.validate(invalidData);
      expect(error).toBeDefined();
    });
  });

});
