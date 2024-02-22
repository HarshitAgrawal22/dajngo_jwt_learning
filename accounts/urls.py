from django.contrib import admin
from django.urls import path,include
from . import views

urlpatterns = [
    path("register/",views.UserRegistrationView.as_view(),name="register"),
    
    
    
    
    path("login/",views.UserLoginView.as_view(),name="login"),
    
    
    
    
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    
    
    
    path("changepassword/",views.UserChangePasswordView.as_view(),name="changepassword"),
    
    
    path("reset-password/",views.SendPasswordResetEmailView.as_view(),name="resetPassword"),
    
    
    
    path("reset-password/<uid>/<token>",views.UserPasswordResetView.as_view(),name="resetpasswordwithid")
    
    ]