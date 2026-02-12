# Django OAuth2 SSO Server

A production-ready OAuth 2.0 authorization server implementing the Authorization Code Flow with PKCE, featuring phone number-based authentication and OTP verification.

## Features

- ✅ **OAuth 2.0 Authorization Code Flow with PKCE** (RFC 7636)
- ✅ **Phone Number Authentication**: Users sign up and login with their mobile number.
- ✅ **SMS OTP Verification**: Integrated with `moni.mn` SMS gateway for verifying phone numbers during registration.
- ✅ **JWT Access Tokens**: Signed using HS256 algorithm.
- ✅ **Refresh Token Rotation**: Secure long-term sessions with automatic token rotation.
- ✅ **Token Introspection** (RFC 7662): Standard endpoint for resource servers to validate tokens.
- ✅ **OIDC-compatible UserInfo**: Returns user profile information.
- ✅ **Session Management**: Server-side sessions with Redis backing.
- ✅ **Token Blacklisting**: Immediate revocation capabilities.
- ✅ **CORS Support**: Configurable Cross-Origin Resource Sharing.

## Tech Stack

- **Framework**: Django 5.2.8 + Django REST Framework 3.16.1
- **Database**: MySQL (default) / SQLite (dev)
- **Cache / Session Store**: Redis
- **Cryptography**: PyJWT + Python Cryptography
- **SMS Gateway**: Custom integration for OTP

## Quick Start

### Prerequisites

- Python 3.10+
- MySQL Server
- Redis Server
- pip

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd django-sso
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # on Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration**
   
   Create a `.env` file in the project root:
   ```env
   SECRET_KEY=your-secure-secret-key-CHANGE-IN-PRODUCTION
   DEBUG=True
   DB_NAME=sso_db
   DB_USER=root
   DB_PASSWORD=yourpassword
   DB_HOST=localhost
   DB_PORT=3306
   REDIS_URL=redis://127.0.0.1:6379/1
   ```

5. **Run Migrations**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Create a Superuser**
   ```bash
   python manage.py createsuperuser
   ```

7. **Start the Server**
   ```bash
   python manage.py runserver
   ```

   The server will start at `http://localhost:8000`.

### Register an OAuth Client

1. Access the Django Admin at `http://localhost:8000/admin`.
2. Navigate to **Ssoauthserver > OAuth Clients**.
3. Create a new client:
   - **Client ID**: `your-client-id`
   - **Client Secret**: Generate a secure string (hashed on save).
   - **Redirect URIs**: `{"redirect_uris": ["http://localhost:8080/callback"]}`
   - **Grant Types**: `["authorization_code", "refresh_token"]`
   - **Response Types**: `["code"]`
   - **Scope**: `openid profile phone`
   - **Is Confidential**: Checked (True).

## Key Components

### Authentication Flow (Phone + OTP)

This server uses a phone-first authentication model. 
1. **Signup**: User enters phone -> receives SMS OTP -> verifies OTP -> sets password.
2. **Login**: User enters phone + password -> receives SSO session.

### Directory Structure

```
django-sso/
├── manage.py
├── mysite/
│   ├── settings.py       # Configuration (DB, Redis, JWT)
│   ├── urls.py          # Root URL conf
│   └── wsgi.py
├── ssoAuthServer/
│   ├── admin.py         # Admin interface
│   ├── models.py        # AuthUser (Phone), OAuthClient, Tokens
│   ├── views.py         # Auth logic (Login, Signup, OAuth Endpoints)
│   ├── urls.py          # App URL conf
│   ├── utils.py         # OTP generation & cache keys
│   └── templates/       # Login/Signup HTML pages
└── requirements.txt
```

## Configuration

**Token Lifetimes** (in `settings.py`):
- Access Token: 15 minutes (default)
- Refresh Token: 30 days (default)
- Authorization Code: 10 minutes (default)

**Redis**: Used for caching OTPs and managing user sessions. Ensure your Redis server is running.

## Testing

For detailed endpoint documentation and testing instructions, please refer to [API_DOCUMENTATION.md](./API_DOCUMENTATION.md).

## License

MIT
