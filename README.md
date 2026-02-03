# Introduction:
The service is a OAuth 2.0 service integrated with AWS Cognito to manage authentication and authorization for the application.
This service exposes REST APIs for user login, registration, token management, and session control.
It acts as the central gateway for identity verification for all other microservices.
The auth project can be deployed to AWS Lambda with AWS SAM. Refer to SAMDEPLOYMENT.md for further details.

# Features:
## Authentication
- User Registration
- User Login
- Token Management (Access/Refresh/ID)
- Token Verification (JWT signature validation, token expiration and claims check)
- User Profile Management (via CognitoUserPool)
- Resend Confirmation Code
## Session Management
- User Logout
- Password Change
- Password Reset (Email-based)
## Security
- JWT-Based Stateless Auth
- CORS Support
- CSRF Protection
- Secure Password Handling
- Comprehensive Error Handling
- Audit Logging
- Sensitive Data Masking
## Authorization (future release)
- Role-based access (user, admin)
- JWT claims propagation to Gateway and other services

# Getting Started:
## Prerequisites:
Ensure you have installed:
- Java 17+
- Maven 3.9+
- AWS CLI (configured with permissions)
- An AWS Account
- Cognito User Pool & App Client
- Docker (optional, for local container run)
- IDE such as IntelliJ or VS Code

## Installation:
### Step 1: AWS Cognito Setup
```bash
aws cognito-idp create-user-pool --pool-name fintracker-users
aws cognito-idp create-user-pool-client --user-pool-id {id} --client-name fintracker-web
```

### Step 2: Configuration
```yaml
# Update application.yaml
aws:
  cognito:
    region: us-east-1
    user-pool-id: your-pool-id
    client-id: your-client-id
```

### Step 3: Run Service
```bash
cd auth
mvn spring-boot:run
```

# Usage:
Invoking APIs to use functions in the service.
## REST API Endpoints

| #   | Endpoint                       | Method | Purpose                         |
|-----|--------------------------------|--------|---------------------------------|
| 1   | /auth/register                 | POST   | User registration               |
| 2   | /auth/login                    | POST   | User authentication             |
| 3   | /auth/refresh                  | POST   | Token refresh                   |
| 4   | /auth/verify                   | GET    | Token verification              |
| 5   | /auth/profile                  | GET    | Get user profile                |
| 6   | /auth/profile/password         | POST   | Change password                 |
| 7   | /auth/logout                   | POST   | Session logout                  |
| 8   | /auth/forgot-password          | POST   | Reset password request          |
| 9   | /auth/reset-password           | POST   | Complete password reset         |
| 10  | /auth/check-email              | GET    | Check email registration        |
| 11  | /auth/confirm-user-email       | POST   | Confirm a registered user email |
| 12  | /auth/resend-confirmation-code | POST   | Resend the confirmation code    |

## Testing
```bash
# Register
curl -X POST http://localhost:8081/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Password123!","fullName":"Test"}'

# Login
curl -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Password123!"}'
  
# Verify confirmation code
curl -X POST http://localhost:8081/api/auth/confirm-user-email \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","confirmationCode":"000000"}'
  
# Verify token
curl -X POST http://localhost:8081/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"accessToken":"YOUR_ACCESS_TOKEN"}'
  
# Get the user's profile
curl -H "Authorization: Bearer YOUR_BEARER_TOKEN" http://localhost:8081/api/auth/profile

# License:
- MIT License
