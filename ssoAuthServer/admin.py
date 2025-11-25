from django.contrib import admin
from .models import AuthUser, OAuthClient, AuthCode, RefreshToken, Session, AccessTokenBlacklist

admin.site.register(AuthUser)
admin.site.register(OAuthClient)
admin.site.register(AuthCode)
admin.site.register(RefreshToken)
admin.site.register(Session)
admin.site.register(AccessTokenBlacklist)