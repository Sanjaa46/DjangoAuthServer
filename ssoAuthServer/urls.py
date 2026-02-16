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
    path("introspect", views.introspect, name="introspect"),
    path('signup/verify', views.signup_verify_view, name='signup_verify'),
    path('signup/set_password', views.set_password_view, name='set_password'),
]