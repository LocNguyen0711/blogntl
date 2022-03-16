from email import message
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login, logout
from .forms import fUserCreate, fCreatePost
from django.core.mail import send_mail
from .models import mCreatePost
from django.contrib.auth.models import User
# Forgot password:
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
# Create your views here.


def index(request):
    posts = mCreatePost.objects.all()
    if request.user.is_authenticated:
        return render(request, "index.html", {
            "posts": posts
        })
    return render(request, "layout.html", {
        "posts": posts
    })


def sign_in(request):
    if request.user.is_authenticated:
        return HttpResponseRedirect(reverse("blog:index"))
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user_login = authenticate(username=username, password=password)
        if user_login is not None:
            login(request, user_login)
            return HttpResponseRedirect(reverse("blog:index"))
        else:
            return render(request, "pages/sign-in.html", {
                "message": "Your account is incorrect!"
            })
    return render(request, "pages/sign-in.html")


def sign_out(request):
    if request.user.is_authenticated:
        logout(request)
        return HttpResponseRedirect(reverse("blog:index"))
    return HttpResponseRedirect(reverse("blog:index"))


def sign_up(request):
    if request.user.is_authenticated:
        logout(request)
        return HttpResponseRedirect(reverse("blog:sign_out"))
    if request.method == "POST":
        form = fUserCreate(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password1"]
            form.save()
            new_user = authenticate(username=username, password=password)
            if new_user is not None:
                login(request, new_user)
                return HttpResponseRedirect(reverse("blog:index"))
        return render(request, "pages/sign-up.html", {
            "form": form
        })
    return render(request, "pages/sign-up.html", {
        "form": fUserCreate()
    })


def user_profile(request):
    if request.user.is_authenticated:
        return render(request, "pages/profile.html")
    return HttpResponseRedirect(reverse("blog:sign_in"))


def new_post(request):
    if request.user.is_authenticated:
        if request.method == "POST":
            form = fCreatePost(request.POST)
            if form.is_valid():
                saveForm = mCreatePost(
                    title=form.cleaned_data["title"], description=form.cleaned_data["description"], body=form.cleaned_data["body"])
                saveForm.author = request.user
                saveForm.save()
                return HttpResponseRedirect(reverse("blog:index"))
            return render(request, "pages/createpost.html", {
                "form": form
            })
        return render(request, "pages/createpost.html", {
            "form": fCreatePost()
        })
    return HttpResponseRedirect(reverse("blog:sign_in"))


def reset_password(request):
    messages = ""
    if request.method == "POST":
        uid = request.session.get('uid')
        user = User.objects.get(pk=uid)
        password1 = request.POST["password1"]
        password2 = request.POST["password2"]
        if (password1 == password2):
            user.set_password(password1)
            user.save()
            messages = "Your password was saved!"
            return HttpResponseRedirect(reverse("blog:sign_in"))
        else:
            messages = "Your password is incorrectly"
    else:
        return HttpResponseRedirect(reverse("blog:sign_in"))
    return render(request, "pages/reset-password.html", {
        "message": messages
    })


def forgot_password(request):
    if request.user.is_authenticated:
        logout(request)
    if request.method == "POST":
        username = request.POST.get("inpUsername")
        try:
            usernameRespone = User.objects.get(username=username)
        except Exception:
            usernameRespone = None
        if(usernameRespone):
            email = request.POST.get("inpEmail")
            emailRespone = usernameRespone.email
            if(email == emailRespone):
                current_site = get_current_site(request=request)
                message = render_to_string('pages/reset-password-email.html', {
                    'user': usernameRespone,
                    'domain': current_site.domain,
                    'uid': (urlsafe_base64_encode(force_bytes(usernameRespone.pk))).encode().decode(),
                    'token': default_token_generator.make_token(usernameRespone)
                })
                send_mail("Email verification", message, "ntloc2001195@student.ctuet.edu.vn", [emailRespone],
                          fail_silently=False)
                return render(request, "pages/forgot-password.html", {
                    "message": "Pleas, check your email to validate!"
                })
            else:
                return render(request, "pages/forgot-password.html", {
                    "message": "Please enter an email connected!"
                })
        else:
            return render(request, "pages/forgot-password.html", {
                "message": "The username does not exist!"
            })
    return render(request, "pages/forgot-password.html")


def reset_password_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except Exception:
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        return render(request, "pages/reset-password.html")
    else:
        return render(request, "index.html")
