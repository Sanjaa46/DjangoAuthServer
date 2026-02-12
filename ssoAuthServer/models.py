from django.db import models
from django.utils import timezone
from django.core.validators import RegexValidator


phone_validator = RegexValidator(
    regex=r'^\+?\d{8,15}$',
    message="Enter a valid phone number in E.164 format."
)


class AuthUser(models.Model):
    id = models.AutoField(primary_key=True)
    phone = models.CharField(
        max_length=15,
        unique=True,
        validators=[phone_validator],
    )
    password_hash = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "ssoAuthServer_authuser"

    def __str__(self):
        return f"{self.phone}"


class OAuthClient(models.Model):
    client_id = models.CharField(max_length=100, primary_key=True)
    client_secret_hash = models.CharField(max_length=256, null=True, blank=True)
    redirect_uris = models.JSONField()
    grant_types = models.JSONField()
    response_types = models.JSONField()
    scope = models.TextField()
    client_name = models.CharField(max_length=150)
    is_confidential = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'ssoAuthServer_oauthclient'
    
    def __str__(self):
        return self.client_id

class AuthCode(models.Model):
    code = models.CharField(max_length=100, primary_key=True)
    user_id = models.ForeignKey(AuthUser, on_delete=models.CASCADE, related_name='auth_codes')
    client_id = models.ForeignKey(OAuthClient, on_delete=models.CASCADE, related_name='auth_codes')
    redirect_uri = models.TextField()
    scope = models.TextField()
    code_challenge = models.CharField(max_length=256, null=True, blank=True)
    code_challenge_method = models.CharField(max_length=10, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    
    class Meta:
        db_table = 'ssoAuthServer_oauthcode'
        indexes = [
            models.Index(fields=['expires_at', 'user_id']),
        ]
    
    def is_expired(self):
        return timezone.now() >= self.expires_at

class RefreshToken(models.Model):
    token = models.CharField(max_length=255, primary_key=True)
    user_id = models.ForeignKey(AuthUser, on_delete=models.CASCADE, related_name='refresh_tokens')
    client_id = models.ForeignKey(OAuthClient, on_delete=models.CASCADE, related_name='refresh_tokens')
    revoked = models.BooleanField(default=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    
    class Meta:
        db_table = 'refresh_token'

class Session(models.Model):
    session_id = models.CharField(max_length=255, primary_key=True)
    user_id = models.ForeignKey(AuthUser, on_delete=models.CASCADE, related_name='sessions')
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    
    class Meta:
        db_table = 'session'

class AccessTokenBlacklist(models.Model):
    jti = models.CharField(max_length=255, primary_key=True)
    revoked_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        db_table = 'access_token_blacklist'