# Django OAuth2 SSO Server - README

A production-ready OAuth 2.0 authorization server implementing the Authorization Code Flow with PKCE.

## Features

- ✅ OAuth 2.0 Authorization Code Flow with PKCE
- ✅ JWT access tokens (HS256)
- ✅ Token introspection (RFC 7662)
- ✅ OIDC-compatible UserInfo endpoint
- ✅ Refresh token rotation
- ✅ Session management
- ✅ Token blacklisting
- ✅ User registration and authentication
- ✅ CORS support

## Quick Start

### Prerequisites

- Python 3.x
- MySQL
- pip

### Installation

1. **Clone the repository**
   ```bash
   cd djangoauthserver
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure database**
   
   Edit `mysite/settings.py`:
   ```python
   DATABASES = {
       'default': {
           'ENGINE': 'django.db.backends.mysql',
           'NAME': 'sso_db',
           'USER': 'root',
           'PASSWORD': 'admin',
           'HOST': 'localhost',
           'PORT': '3306',
       }
   }
   ```

4. **Run migrations**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

5. **Create superuser**
   ```bash
   python manage.py createsuperuser
   ```

6. **Start the server**
   ```bash
   python manage.py runserver
   ```

7. **Access Django Admin**
   
   Navigate to `http://localhost:8000/admin` and login with superuser credentials.

### Register OAuth Client

1. Go to Django Admin → **OAuth Clients**
2. Click **Add OAuth Client**
3. Fill in:
   - **Client ID**: `your_client_id`
   - **Client Secret**: Generate a secure secret
   - **Redirect URIs**: 
     ```json
     {"redirect_uris": ["http://localhost:8080/callback"]}
     ```
   - **Grant Types**: `["authorization_code", "refresh_token"]`
   - **Response Types**: `["code"]`
   - **Scope**: `openid profile email`
   - **Client Name**: Your App Name
   - **Is Confidential**: ✓ (checked)

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/authorize` | GET | OAuth authorization |
| `/token` | POST | Token exchange/refresh |
| `/introspect` | POST | Token validation |
| `/userinfo` | GET | User information |
| `/logout` | GET/POST | Logout |
| `/signup` | GET/POST | User registration |
| `/api/signup` | POST | API user registration |
| `/.well-known/jwks.json` | GET | Public keys |

See [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) for complete details.

## Configuration

### Token Lifetimes

Edit `mysite/settings.py`:

```python
SSO_ACCESS_TOKEN_EXP = 900  # 15 minutes
SSO_REFRESH_TOKEN_EXP = 60 * 60 * 24 * 30  # 30 days
```

### CORS Settings

```python
CORS_ALLOWED_ORIGINS = [
    "http://localhost:8080",
    "http://127.0.0.1:8080",
]
```

## Testing

### Using Postman

See [Postman Testing Guide](../../../.gemini/antigravity/brain/93cb701f-6cbf-42d4-bb61-ddd6e95260ba/postman_testing_guide.md) for detailed testing instructions.

### Quick Test

1. **Create a test user:**
   ```bash
   curl -X POST http://localhost:8000/api/signup \
     -H "Content-Type: application/json" \
     -d '{"username":"testuser","email":"test@example.com","password":"Test123!"}'
   ```

2. **Get authorization code** (browser):
   ```
   http://localhost:8000/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid%20profile%20email&state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
   ```

3. **Exchange for tokens:**
   ```bash
   curl -X POST http://localhost:8000/token \
     -H "Content-Type: application/json" \
     -d '{"grant_type":"authorization_code","code":"AUTH_CODE","redirect_uri":"http://localhost:8080/callback","client_id":"YOUR_CLIENT_ID","code_verifier":"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}'
   ```

## Database Schema

### Tables

- `ssoAuthServer_authuser` - User accounts
- `ssoAuthServer_oauthclient` - OAuth clients
- `ssoAuthServer_oauthcode` - Authorization codes
- `refresh_token` - Refresh tokens
- `session` - SSO sessions
- `access_token_blacklist` - Revoked tokens

See [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) for detailed schema.

## Security

### Production Checklist

- [ ] Use HTTPS for all endpoints
- [ ] Set `DEBUG = False`
- [ ] Generate strong `SECRET_KEY`
- [ ] Set `SESSION_COOKIE_SECURE = True`
- [ ] Set `ALLOWED_HOSTS` appropriately
- [ ] Implement rate limiting
- [ ] Enable audit logging
- [ ] Set up token cleanup cron job
- [ ] Use environment variables for secrets
- [ ] Configure firewall rules

### Current Security Features

- ✅ PKCE required for authorization code flow
- ✅ Password hashing (PBKDF2-SHA256)
- ✅ Token rotation on refresh
- ✅ Token blacklisting
- ✅ Session expiration
- ✅ CORS protection
- ✅ CSRF protection

## Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Find process using port 8000
lsof -i :8000
# Kill the process
kill -9 <PID>
```

**Database connection error:**
- Verify MySQL is running
- Check database credentials in `settings.py`
- Ensure database `sso_db` exists

**CORS errors:**
- Add client origin to `CORS_ALLOWED_ORIGINS`
- Ensure `CORS_ALLOW_CREDENTIALS = True`

## Project Structure

```
django-sso/
├── manage.py
├── mysite/
│   ├── settings.py       # Django settings
│   ├── urls.py          # URL routing
│   └── wsgi.py
├── ssoAuthServer/
│   ├── models.py        # Data models
│   ├── views.py         # API endpoints
│   ├── urls.py          # App URLs
│   ├── admin.py         # Django admin config
│   └── keys/            # JWT keys
├── requirements.txt     # Python dependencies
└── API_DOCUMENTATION.md # Complete API docs
```

## Dependencies

```
Django==5.2.8
djangorestframework
django-cors-headers
PyJWT
mysqlclient
```

## License

MIT

## Support

For detailed API documentation, see [API_DOCUMENTATION.md](./API_DOCUMENTATION.md)

For testing guide, see [Postman Testing Guide](../../../.gemini/antigravity/brain/93cb701f-6cbf-42d4-bb61-ddd6e95260ba/postman_testing_guide.md)
