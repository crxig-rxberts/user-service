# User Service

This service handles user registration and authentication via AWS Cognito.

## Prerequisites

- Docker and Docker Compose installed.
- An existing AWS Cognito User Pool is required for user authentication.
- Ensure a `.env` file exists with the required environment variables.

## Cognito Requirements

You must have an existing Cognito User Pool set up in AWS. The following details are needed:

- `COGNITO_USER_POOL_ID`: The ID of your Cognito User Pool.
- `COGNITO_CLIENT_ID`: The Client ID of your application registered with the Cognito User Pool.
- `COGNITO_CLIENT_SECRET`: The Client Secret of your application registered with the Cognito User Pool (if applicable).

## Environment Variables

- `AWS_REGION`: The AWS region where your Cognito User Pool is located.
- `AWS_ACCESS_KEY_ID`: Your AWS Access Key ID.
- `AWS_SECRET_ACCESS_KEY`: Your AWS Secret Access Key.
- `COGNITO_USER_POOL_ID`: The ID of your Cognito User Pool.
- `COGNITO_CLIENT_ID`: The Client ID for your Cognito application.
- `COGNITO_CLIENT_SECRET`: The Client Secret for your Cognito application (if applicable).
- `PORT`: The port the service will run on (default: `3000`).

## Example `.env` file:

```
AWS_REGION=eu-west-1
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
COGNITO_USER_POOL_ID=your-user-pool-id
COGNITO_CLIENT_ID=your-client-id
COGNITO_CLIENT_SECRET=your-client-secret
PORT=3000
```
