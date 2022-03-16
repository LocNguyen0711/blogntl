from django.urls import path, re_path
from . import views

app_name = "blog"

urlpatterns = [
    path('', views.index, name="index"),
    path('sign-in/', views.sign_in, name="sign_in"),
    path('sign-out/', views.sign_out, name="sign_out"),
    path('sign-up/', views.sign_up, name="sign_up"),
    path('profile/', views.user_profile, name="user_profile"),
    path('new-post/', views.new_post, name="new_post"),
    path('reset-password/' , views.reset_password, name="reset_password"),
    path('forgot-password/', views.forgot_password, name="forgot_password"),
    path('reset-password-validate/<uidb64>/<token>/', views.reset_password_validate, name="reset_password_validate"),
]
