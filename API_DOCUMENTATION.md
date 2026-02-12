# Django OAuth2 SSO Server - API Documentation

**Version**: 1.0  
**Base URL**: `http://localhost:8000`  
**Protocol**: OAuth 2.0 Authorization Code Flow with PKCE  

---

## Table of Contents

1. [Data Models](#data-models)
2. [User Registration (Phone + OTP)](#user-registration-phone--otp)
3. [Authentication & Session](#authentication--session)
4. [OAuth 2.0 Endpoints](#oauth-20-endpoints)
5. [Token Management](#token-management)
6. [Error Codes](#error-codes)

---

## Data Models

### 1. AuthUser
Custom user model based on phone number.

| Field | Type | Description |
|-------|------|-------------|
| `id` | AutoField | Primary Key |
| `phone` | CharField | **Unique**. E.164 format (e.g., `+97612345678`) or local format. |
| `password_hash` | CharField | PBKDF2 hashed password. |
| `is_active` | Boolean | Account status. |
| `created_at` | DateTime | Account creation timestamp. |

### 2. OAuthClient
Registered client applications.

| Field | Type | Description |
|-------|------|-------------|
| `client_id` | CharField | Unique Client ID. |
| `client_secret_hash` | CharField | Hashed client secret. |
| `redirect_uris` | JSONField | List of allowed callback URLs. |
| `grant_types` | JSONField | e.g. `["authorization_code", "refresh_token"]`. |
| `is_confidential` | Boolean | `True` for server-side apps. |

---

## User Registration (Phone + OTP)

The registration process follows a strict 3-step flow:

### 1. Send OTP
Request an OTP to verify the phone number.

- **Endpoint**: `POST /signup`
- **Content-Type**: `application/x-www-form-urlencoded`

**Parameters:**

| Name | Required | Description |
|------|----------|-------------|
| `phone` | Yes | User's phone number. |
| `client_id` | No | Forwarded OAuth param. |

**Response (200 OK):**
```json
{
  "result": "otp_sent"
}
```

### 2. Confirm OTP
Verify the received OTP code.

- **Endpoint**: `POST /confirm_otp`

**Parameters:**

| Name | Required | Description |
|------|----------|-------------|
| `phone` | Yes | Phone number used in step 1. |
| `otp` | Yes | 4-digit code received via SMS. |

**Response (200 OK):**
Returns a temporary `pwd_token` valid for 10 minutes.
```json
{
  "result": "otp_verified",
  "pwd_token": "temporary-secure-token-string"
}
```

### 3. Set Password
Finalize account creation by setting a password.

- **Endpoint**: `POST /set_password`

**Parameters:**

| Name | Required | Description |
|------|----------|-------------|
| `pwd_token` | Yes | Token received from `/confirm_otp`. |
| `password` | Yes | New password (min 8 chars). |
| `password_confirm` | Yes | Must match `password`. |

**Response (201 Created):**
```json
{
  "result": "user_created",
  "user_id": 123
}
```

---

## Authentication & Session

### Login Page
Renders the HTML login form.

- **Endpoint**: `GET /login`
- **Query Params**: Standard OAuth2 params (`client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `code_challenge`, `code_challenge_method`).

### Perform Login
Authenticates user creds and creates an SSO session.

- **Endpoint**: `POST /login`
- **Form Data**: `phone`, `password` + OAuth params hidden fields.
- **Behavior**: On success, redirects to `/authorize` with original query params to continue OAuth flow.

---

## OAuth 2.0 Endpoints

### 1. Authorization Endpoint
Initiates the OAuth 2.0 flow.

- **Endpoint**: `GET /authorize`
- **Params**:
    - `client_id` (required)
    - `redirect_uri` (required)
    - `response_type=code` (required)
    - `code_challenge` (required, PKCE S256)
    - `code_challenge_method=S256` (required)
    - `scope` (optional)
    - `state` (recommended)

**Success**: Redirects to `redirect_uri` with `code` and `state`.

### 2. Token Endpoint
Exchange authorization code for tokens.

- **Endpoint**: `POST /token`
- **Content-Type**: `application/json` or `application/x-www-form-urlencoded`

#### Grant Type: Authorization Code
```json
{
  "grant_type": "authorization_code",
  "code": "AUTH_CODE_FROM_CALLBACK",
  "redirect_uri": "http://localhost:8080/callback",
  "client_id": "your-client-id",
  "code_verifier": "PKCE_VERIFIER_STRING"
}
```

#### Grant Type: Refresh Token
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "EXISTING_REFRESH_TOKEN_STRING",
  "client_id": "your-client-id"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1Ni...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "new-refresh-token-string"
}
```

### 3. UserInfo Endpoint
Get authenticated user details.

- **Endpoint**: `GET /userinfo`
- **Headers**: `Authorization: Bearer <access_token>`

**Response (200 OK):**
```json
{
  "sub": "123",
  "phone": "99112233"
}
```

### 4. Introspection Endpoint (RFC 7662)
Validate a token from a resource server.

- **Endpoint**: `POST /introspect`
- **Auth**: Basic Auth (`client_id:client_secret`) OR Form params.
- **Body**: `token=<access_token_or_refresh_token>`

**Response (200 OK):**
```json
{
  "active": true,
  "scope": "openid profile",
  "client_id": "your-client-id",
  "phone": "99112233",
  "sub": "123",
  "exp": 1700000000,
  "iat": 1690000000,
  "jti": "token-id"
}
```

### 5. Logout Endpoint
Terminates the server-side SSO session.

- **Endpoint**: `GET /logout`
- **Params**:
  - `post_logout_redirect_uri`: URL to redirect after logout.
  - `client_id`: To validate the redirect URI.

- **Endpoint**: `POST /logout` (RP-Initiated)
- **Body**: `token=<refresh_token>`
- **Behavior**: Revokes the specific refresh token.

---

## Token Management

### Access Token (JWT)
- **Algorithm**: HS256
- **Lifetime**: 15 minutes
- **Payload**:
  - `sub`: User ID
  - `phone`: User Phone
  - `client_id`: Client ID
  - `jti`: Unique Token ID (used for blacklisting)

### Refresh Token
- **Format**: Opaque URL-safe string (48 bytes)
- **Lifetime**: 30 days
- **Storage**: Hashed in database.
- **Rotation**: A new refresh token is issued every time an old one is used. The old one is immediately revoked.

### PKCE (Proof Key for Code Exchange)
This server **enforces** PKCE for the authorization code flow.
- `code_challenge_method` must be `S256`.
- `code_verifier` must be provided during token exchange.

---

## Error Codes

Common error responses follow OAuth 2.0 specs:

- `invalid_request`: Missing parameter.
- `invalid_client`: Authentication failed.
- `invalid_grant`: Expired or invalid code/token.
- `unauthorized_client`: Client not allowed to use this grant type.
- `unsupported_grant_type`: Grant type not supported.
- `invalid_scope`: Scope is invalid.

HTTP Status Codes:
- `200`: Success
- `302`: Redirect (Authorize flow)
- `400`: Bad Request (Validation error)
- `401`: Unauthorized (Invalid token/credentials)
- `500`: Server Error
