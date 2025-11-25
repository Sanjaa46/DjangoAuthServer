from django.urls import path
from . import views

urlpatterns =[
    path('.well-known/jwks.json', views.jwks_view),
    path("authorize", views.authorize, name="authorize"),
    path("login", views.login_view, name="login"),
    path("token", views.token, name="token"),
    path("logout", views.logout_view, name="logout"),
    path("userinfo", views.userinfo, name="userinfo"),
    path("signup", views.signup_view, name="signup"),
    path("api/signup", views.api_signup, name="api_signup"),
]