from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST, require_GET
from django.conf import settings
from ssoAuthServer.utils import otp_cache_key, pwd_token_cache_key
from pathlib import Path
import requests
import json
import urllib.parse
from datetime import timedelta
from django.shortcuts import render, redirect
from django.utils import timezone
from django.http import HttpResponseBadRequest
from django.contrib.auth import logout as django_logout
from .models import OAuthClient, AuthCode, Session, RefreshToken, AuthUser, AccessTokenBlacklist
import base64
from django.contrib.auth.hashers import check_password
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.core.cache import cache
import random
import jwt
import uuid
import secrets
import hashlib

def send_sms(phone, text):
    try:
        SMS_URL = "https://callpro.moni.mn/api/method/monify_sms.message.send_msg"
        SMS_TIMEOUT = 10
        payload = {"utas_dugaar": phone, "text": text, "type": "otp", "doctype": "Daily"}
        r = requests.post(SMS_URL, json=payload, timeout=SMS_TIMEOUT)
        if r.status_code != 200:
            print(f"SMS failed [{r.status_code}]: {r.text}", "send_sms")
            return "error"
        return "ok"
    except Exception:
        print("send_sms exception", "send_sms")
        return "error"

def jwks_view(request):
    jwks_path = Path("ssoAuthServer/keys/jwks.json")
    if not jwks_path.exists():
        return JsonResponse({"error": "jwks not found"}, status=404)
    jwks = json.loads(jwks_path.read_text().replace("'", '"'))
    return JsonResponse(jwks)

def signup_view(request):
    """
    HTML Signup Page (GET + POST)
    GET: Renders signup form
    POST: Generates OTP and sends via SMS
    """

    # Extract OAuth params (must be passed back to login)
    oauth_params = {
        "client_id": request.GET.get("client_id") or request.POST.get("client_id"),
        "redirect_uri": request.GET.get("redirect_uri") or request.POST.get("redirect_uri"),
        "response_type": request.GET.get("response_type") or request.POST.get("response_type"),
        "scope": request.GET.get("scope") or request.POST.get("scope"),
        "state": request.GET.get("state") or request.POST.get("state"),
        "code_challenge": request.GET.get("code_challenge") or request.POST.get("code_challenge"),
        "code_challenge_method": request.GET.get("code_challenge_method") or request.POST.get("code_challenge_method"),
    }

    if request.method == "GET":
        return render(request, "signup.html", {"params": oauth_params})

    # POST - Send OTP
    phone = request.POST.get("phone")

    if not phone:
        return JsonResponse({"error": "phone_required"}, status=400)

    # Check if phone exists
    if AuthUser.objects.filter(phone=phone).exists():
        return JsonResponse({"error": "phone_already_exists"}, status=400)

    # Generate and cache OTP
    key = otp_cache_key(phone, "signup")
    otp = f"{random.randint(1000, 9999)}"
    cache.set(key, otp, timeout=300)  # OTP valid for 5 minutes
    
    # Send SMS
    msg = f"OmniCapital: Таны баталгаажуулах код: {otp}. Код 5 минут хүчинтэй."
    res = send_sms(phone, msg)

    if res != "ok":
        return JsonResponse({"error": "sms_failed"}, status=500)
    
    return JsonResponse({"result": "otp_sent"}, status=200)

def confirm_otp_view(request):
    """
    Verify OTP and return password token
    POST: Verifies OTP from cache and returns a pwd_token for password setup
    """
    if request.method != "POST":
        return JsonResponse({"error": "invalid_method"}, status=405)

    phone = request.POST.get("phone")
    otp = request.POST.get("otp")

    if not phone or not otp:
        return JsonResponse({"error": "phone_and_otp_required"}, status=400)

    # Check if phone already exists
    if AuthUser.objects.filter(phone=phone).exists():
        return JsonResponse({"error": "phone_already_exists"}, status=400)

    # Verify OTP from cache
    key = otp_cache_key(phone, "signup")
    cached_otp = cache.get(key)

    if not cached_otp:
        return JsonResponse({"error": "otp_expired"}, status=400)

    if cached_otp != otp:
        return JsonResponse({"error": "invalid_otp"}, status=400)

    # OTP is valid - delete it from cache
    cache.delete(key)

    # Generate password token
    pwd_token = secrets.token_urlsafe(32)
    
    # Store phone number with pwd_token in cache (valid for 10 minutes)
    token_key = pwd_token_cache_key(pwd_token)
    cache.set(token_key, phone, timeout=600)

    return JsonResponse({
        "result": "otp_verified",
        "pwd_token": pwd_token
    }, status=200)


def set_password_view(request):
    """
    Set password for verified phone number
    POST: Verifies pwd_token, creates user, and sets password
    """
    if request.method != "POST":
        return JsonResponse({"error": "invalid_method"}, status=405)

    pwd_token = request.POST.get("pwd_token")
    password = request.POST.get("password")
    password_confirm = request.POST.get("password_confirm")

    if not pwd_token or not password:
        return JsonResponse({"error": "pwd_token_and_password_required"}, status=400)

    # Verify passwords match
    if password != password_confirm:
        return JsonResponse({"error": "passwords_do_not_match"}, status=400)

    # Verify password token and get phone number
    token_key = pwd_token_cache_key(pwd_token)
    phone = cache.get(token_key)

    if not phone:
        return JsonResponse({"error": "invalid_or_expired_token"}, status=400)

    # Check if user already exists (safety check)
    if AuthUser.objects.filter(phone=phone).exists():
        cache.delete(token_key)
        return JsonResponse({"error": "user_already_exists"}, status=400)

    # Validate password strength (optional - add your own rules)
    if len(password) < 8:
        return JsonResponse({"error": "password_too_short"}, status=400)

    # Create user and set password
    try:
        user = AuthUser.objects.create(
            phone=phone,
            password_hash=make_password(password),
            is_active=True
        )
        
        # Delete the password token from cache
        cache.delete(token_key)

        return JsonResponse({
            "result": "user_created",
            "user_id": user.id
        }, status=201)

    except Exception as e:
        return JsonResponse({"error": f"user_creation_failed: {str(e)}"}, status=500)



def authorize(request):
    """
    Implements OAuth2 Authorization Code Flow with PKCE.
    """
    # Required params
    client_id = request.GET.get("client_id")
    redirect_uri = request.GET.get("redirect_uri")
    response_type = request.GET.get("response_type")
    scope = request.GET.get("scope", "")
    state = request.GET.get("state", "")
    code_challenge = request.GET.get("code_challenge")
    code_challenge_method = request.GET.get("code_challenge_method")

    # 1. Validate mandatory params
    if not client_id or not redirect_uri or not response_type:
        return HttpResponseBadRequest("Missing required parameters")

    if response_type != "code":
        return HttpResponseBadRequest("Unsupported response_type")

    # 2. Validate client
    try:
        client = OAuthClient.objects.get(pk=client_id)
    except OAuthClient.DoesNotExist:
        return HttpResponseBadRequest("Invalid client_id")

    # 3. Check redirect_uri is allowed
    if isinstance(client.redirect_uris, dict):
        allowed_uris = client.redirect_uris.get("redirect_uris", [])
    else:
        allowed_uris = client.redirect_uris
    

    if redirect_uri not in allowed_uris:
        return HttpResponseBadRequest("Invalid redirect_uri")

    # 4. Check existing SSO session
    user_session_id = request.session.get("sso_session_id")

    if not user_session_id:
        # No SSO session → show login page
        login_url = (
            "/login?"
            + urllib.parse.urlencode({
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
            })
        )
        return redirect(login_url)

    # Validate session object
    try:
        sso_session = Session.objects.get(pk=user_session_id)
    except Session.DoesNotExist:
        # Session missing → force login
        login_url = (
            "/login?"
            + urllib.parse.urlencode({
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
            })
        )
        return redirect(login_url)

    if sso_session.expires_at < timezone.now():
        # Session expired → logout & force login
        django_logout(request)
        login_url = (
            "/login?"
            + urllib.parse.urlencode({
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
            })
        )
        return redirect(login_url)
    # sso_session = Session.objects.get(pk="1")
    # 5. User is authenticated → issue authorization code
    code = secrets.token_urlsafe(32)

    AuthCode.objects.create(
        code=code,
        user_id_id=sso_session.user_id_id,
        client_id_id=client,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        expires_at=timezone.now() + timedelta(minutes=10)
    )

    # 6. Redirect back to client app
    query = {
        "code": code
    }
    if state:
        query["state"] = state

    final_redirect = redirect_uri + "?" + urllib.parse.urlencode(query)
    # return redirect(final_redirect)
    return JsonResponse({
        "success": True,
        "code": code,
        "state": state,
        "redirect_uri": final_redirect,
    })

@csrf_exempt
def login_view(request):
    """
    GET: render login page
    POST: validate credentials, create SSO session, redirect to /authorize
    """

    # Extract all OAuth parameters (they MUST be forwarded back to /authorize)
    oauth_params = {
        "client_id": request.GET.get("client_id") or request.POST.get("client_id"),
        "redirect_uri": request.GET.get("redirect_uri") or request.POST.get("redirect_uri"),
        "response_type": request.GET.get("response_type") or request.POST.get("response_type"),
        "scope": request.GET.get("scope") or request.POST.get("scope"),
        "state": request.GET.get("state") or request.POST.get("state"),
        "code_challenge": request.GET.get("code_challenge") or request.POST.get("code_challenge"),
        "code_challenge_method": request.GET.get("code_challenge_method") or request.POST.get("code_challenge_method"),
    }

    # GET → show login page
    if request.method == "GET":
        return render(request, "login.html", {"params": oauth_params})

    # POST → handle login
    # body = json.loads(request.body.decode())
    phone = request.POST.get("phone")
    password = request.POST.get("password")

    if not phone or not password:
        messages.error(request, "Phone and password required")
        return render(request, "login.html", {"params": oauth_params})


    # Authenticate user (manual — because you're not using Django's User)
    try:
        user = AuthUser.objects.get(phone=phone)
    except AuthUser.DoesNotExist:
        messages.error(request, "Invalid phone or password")
        return render(request, "login.html", {"params": oauth_params})

    if not user.is_active:
        messages.error(request, "User is disabled")
        return render(request, "login.html", {"params": oauth_params})

    # Compare hashed password
    if not check_password(password, user.password_hash):
        messages.error(request, "Invalid phone or password")
        return render(request, "login.html", {"params": oauth_params})

    # Create SSO session
    expires_at = timezone.now() + timedelta(hours=12)
    sso_session = Session.objects.create(
        session_id=str(uuid.uuid4()),
        user_id_id=user,
        expires_at=expires_at,
    )

    # Store session ID inside Django session cookie
    request.session["sso_session_id"] = sso_session.session_id

    # Redirect back to /authorize with all params
    qs = urllib.parse.urlencode({k: v for k, v in oauth_params.items() if v})
    # return redirect(f"/authorize?{qs}")
    return HttpResponse(qs, content_type="text/plain")

def generate_jwt(user, client_id):
    """
    Create access token JWT.
    """
    payload = {
        "sub": str(user.id),
        "phone": user.phone,
        "client_id": client_id,
        "exp": timezone.now() + timedelta(minutes=15),
        "iat": timezone.now(),
        "jti": secrets.token_urlsafe(12)
    }

    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


@csrf_exempt
def token(request):
    if request.method != "POST":
        return JsonResponse({"error": "invalid_request"}, status=400)

    body = json.loads(request.body.decode())
    
    # grant_type = request.POST.get("grant_type")
    grant_type = body.get("grant_type")

    # ---------------------------------------------------------
    # 1. AUTHORIZATION CODE EXCHANGE
    # ---------------------------------------------------------
    if grant_type == "authorization_code":
        code = body.get("code")
        redirect_uri = body.get("redirect_uri")
        client_id = body.get("client_id")
        code_verifier = body.get("code_verifier")

        # Validate required fields
        if not all([code, redirect_uri, client_id]):
            return JsonResponse({"error": "invalid_request"}, status=400)

        try:
            auth_code = AuthCode.objects.get(code=code)
        except AuthCode.DoesNotExist:
            return JsonResponse({"error": "invalid_grant"}, status=400)

        # Check expiration
        if auth_code.expires_at < timezone.now():
            auth_code.delete()
            return JsonResponse({"error": "invalid_grant"}, status=400)

        # Check redirect URI
        if auth_code.redirect_uri != redirect_uri:
            return JsonResponse({"error": "invalid_grant"}, status=400)

        # PKCE verification
        if auth_code.code_challenge == "None":
            if not code_verifier:
                return JsonResponse({"error": "invalid_request"}, status=400)

            verifier_hash = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).rstrip(b"=").decode()

            if verifier_hash != auth_code.code_challenge:
                return JsonResponse({"error": "invalid_grant"}, status=400)

        # Issue tokens
        user = AuthUser.objects.get(pk=auth_code.user_id_id)

        access_token = generate_jwt(user, client_id)
        refresh_token = secrets.token_urlsafe(48)

        # Save refresh token
        RefreshToken.objects.create(
            token=refresh_token,
            user_id_id=user,
            client_id_id=auth_code.client_id_id,
            expires_at=timezone.now() + timedelta(days=30),
        )

        # Delete code after use (one-time)
        auth_code.delete()

        return JsonResponse({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": refresh_token,
        })

    # ---------------------------------------------------------
    # 2. REFRESH TOKEN FLOW
    # ---------------------------------------------------------
    elif grant_type == "refresh_token":
        refresh_token_val = request.POST.get("refresh_token")
        client_id = request.POST.get("client_id")

        if not refresh_token_val or not client_id:
            return JsonResponse({"error": "invalid_request"}, status=400)

        try:
            rt = RefreshToken.objects.get(token=refresh_token_val, revoked=False)
        except RefreshToken.DoesNotExist:
            return JsonResponse({"error": "invalid_grant"}, status=400)

        if rt.expires_at < timezone.now():
            rt.revoked = True
            rt.save()
            return JsonResponse({"error": "invalid_grant"}, status=400)

        # Rotate refresh token (security best practice)
        new_refresh = secrets.token_urlsafe(48)

        rt.revoked = True
        rt.save()

        RefreshToken.objects.create(
            token=new_refresh,
            user=rt.user,
            client=rt.client,
            expires_at=timezone.now() + timedelta(days=30),
        )

        new_access = generate_jwt(rt.user, client_id)

        return JsonResponse({
            "access_token": new_access,
            "token_type": "Bearer",
            "expires_in": 900,
            "refresh_token": new_refresh,
        })

    # ---------------------------------------------------------
    # 3. UNSUPPORTED GRANT TYPE
    # ---------------------------------------------------------
    return JsonResponse({"error": "unsupported_grant_type"}, status=400)


def _authenticate_client(request):
    """
    Supports HTTP Basic auth or form-based client_id/client_secret.
    Returns OAuthClient instance or None.
    """
    # 1) HTTP Basic
    auth_header = request.META.get("HTTP_AUTHORIZATION")
    if auth_header and auth_header.startswith("Basic "):
        try:
            raw = base64.b64decode(auth_header.split(" ", 1)[1].strip()).decode()
            client_id, client_secret = raw.split(":", 1)
        except (ValueError, IndexError, TypeError):
            return None
    else:
        client_id = request.POST.get("client_id")
        client_secret = request.POST.get("client_secret")
        if not client_id or not client_secret:
            return None

    try:
        client = OAuthClient.objects.get(pk=client_id)
    except OAuthClient.DoesNotExist:
        return None

    if not client.client_secret_hash:
        # public client — cannot authenticate with secret
        return None

    if not check_password(client_secret, client.client_secret_hash):
        return None

    return client

@csrf_exempt
@require_POST
def introspect(request):
    """
    RFC 7662 token introspection endpoint.
    POST params: token=<token>
    Auth: HTTP Basic (client_id:client_secret) OR client_id+client_secret in form.
    """
    # authenticate client (recommended for introspection)
    client = _authenticate_client(request)
    if client is None:
        # for some deployments you may allow anonymous introspect for public tokens,
        # but default to requiring client auth
        return JsonResponse({"error": "invalid_client"}, status=401)
    token = request.POST.get("token")
    if not token:
        return JsonResponse({"error": "invalid_request"}, status=400)

    # 1) Check if token is a revoked access token jti in blacklist
    # If client previously included "jti" when issuing JWTs, clients may pass the JWT.
    try:
        # Try decode as JWT (HS256 used by current implementation)
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"], options={"verify_aud": False})
        # jwt.decode raises if invalid / expired
        exp_ts = payload.get("exp")
        active = True if (not exp_ts or exp_ts > int(timezone.now().timestamp())) else False

        # Check blacklist if jti present
        jti = payload.get("jti")
        if jti and AccessTokenBlacklist.objects.filter(jti=jti).exists():
            active = False

        response = {
            "active": active,
            "scope": payload.get("scope"),
            "client_id": payload.get("client_id"),
            "username": payload.get("username"),
            "sub": payload.get("sub"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat"),
            "jti": payload.get("jti"),
        }
        return JsonResponse(response)
    except jwt.ExpiredSignatureError:
        return JsonResponse({"active": False})
    except jwt.InvalidTokenError:
        # Not a JWT — maybe an opaque refresh token stored in DB
        try:
            rt = RefreshToken.objects.get(token=token)
            active = (not rt.revoked) and (rt.expires_at > timezone.now())
            resp = {
                "active": active,
                "client_id": rt.client.client_id if rt.client else None,
                "sub": str(rt.user.id),
                "username": rt.user.username,
                "exp": int(rt.expires_at.timestamp()) if rt.expires_at else None,
                "scope": None,
            }
            return JsonResponse(resp)
        except RefreshToken.DoesNotExist:
            return JsonResponse({"active": False})

@csrf_exempt
def logout_view(request):
    """
    Supports:
    - GET: user-initiated logout (destroy SSO session cookie), optional redirect back to client.
      Query params: post_logout_redirect_uri, client_id
    - POST: RP-initiated logout (requires client auth). Form params: token (refresh token or id_token_hint)
    """
    if request.method == "GET":
        post_logout_redirect_uri = request.GET.get("post_logout_redirect_uri")
        client_id = request.GET.get("client_id")

        # Destroy Django session / SSO session mapping
        sso_session_id = request.session.pop("sso_session_id", None)
        if sso_session_id:
            try:
                s = Session.objects.get(pk=sso_session_id)
                s.delete()
            except Session.DoesNotExist:
                pass

        django_logout(request)

        # Validate redirect URI against client list if provided
        if post_logout_redirect_uri and client_id:
            try:
                client = OAuthClient.objects.get(pk=client_id)
                allowed = client.redirect_uris.get("redirect_uris", [])
                
                # For logout, be more flexible - allow base URLs
                from urllib.parse import urlparse
                redirect_base = urlparse(post_logout_redirect_uri).netloc
                
                for allowed_uri in allowed:
                    if urlparse(allowed_uri).netloc == redirect_base:
                        return redirect(post_logout_redirect_uri)
            except OAuthClient.DoesNotExist:
                pass

        return HttpResponse("Logged out successfully", status=200)


    elif request.method == "POST":
        # RP-initiated: require client auth
        client = _authenticate_client(request)
        if client is None:
            return JsonResponse({"error": "invalid_client"}, status=401)

        token = request.POST.get("token")
        if not token:
            return JsonResponse({"error": "invalid_request"}, status=400)

        # If token is a refresh token: revoke it
        try:
            rt = RefreshToken.objects.get(token=token)
            rt.revoked = True
            rt.save()

            # Optionally revoke all refresh tokens of that user/client
            RefreshToken.objects.filter(user=rt.user, client=client).update(revoked=True)
            return JsonResponse({"result": "revoked"})
        except RefreshToken.DoesNotExist:
            # If token looks like a JWT, try decode and blacklist jti
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"], options={"verify_aud": False})
                jti = payload.get("jti")
                if jti:
                    AccessTokenBlacklist.objects.get_or_create(jti=jti)
                    return JsonResponse({"result": "access_token_blacklisted"})
            except jwt.InvalidTokenError:
                pass

        # nothing found
        return JsonResponse({"error": "invalid_token"}, status=400)

def extract_bearer_token(request):
    """
    Parse 'Authorization: Bearer <token>' header.
    """
    auth_header = request.META.get("HTTP_AUTHORIZATION")
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]

    return None


@require_GET
def userinfo(request):
    """
    Returns user information for a valid access token.
    Compatible with OpenID Connect style.
    """
    token = extract_bearer_token(request)
    if not token:
        return JsonResponse(
            {"error": "invalid_request", "error_description": "Missing access token"},
            status=401
        )

    # Try decode JWT
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=["HS256"],
            options={"verify_aud": False}
        )
    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "invalid_token", "error_description": "Expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "invalid_token"}, status=401)

    # Check blacklist if jti is present
    jti = payload.get("jti")
    if jti and AccessTokenBlacklist.objects.filter(jti=jti).exists():
        return JsonResponse({"error": "invalid_token"}, status=401)

    # Extract user
    sub = payload.get("sub")
    try:
        user = AuthUser.objects.get(pk=sub)
    except AuthUser.DoesNotExist:
        return JsonResponse({"error": "invalid_token"}, status=401)

    # ---- Build userinfo response ----
    data = {
        "sub": str(user.id),
        "phone": user.phone,
    }

    return JsonResponse(data)