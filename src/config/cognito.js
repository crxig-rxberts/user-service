const AWS = require('aws-sdk');

AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider();

module.exports = {
  cognitoIdentityServiceProvider,
  userPoolId: process.env.COGNITO_USER_POOL_ID,
  clientId: process.env.COGNITO_CLIENT_ID,
  clientSecret: process.env.COGNITO_CLIENT_SECRET
};