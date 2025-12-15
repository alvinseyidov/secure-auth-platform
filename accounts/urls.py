from django.urls import path

from .api import CSRFTokenView, LoginView, LogoutView, RefreshView

urlpatterns = [
    path('csrf/', CSRFTokenView.as_view(), name='api_csrf'),
    path('login/', LoginView.as_view(), name='api_login'),
    path('refresh/', RefreshView.as_view(), name='api_refresh'),
    path('logout/', LogoutView.as_view(), name='api_logout'),
]
