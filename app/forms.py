from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

from app.models import mCreatePost

class fUserLogin(forms.Form):
    username = forms.CharField(widget=forms.TextInput)
    password = forms.PasswordInput()
    def __str__(self):
        return f"{self.id} - {self.username} - {self.password}"
class fUserCreate(UserCreationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'placeholder': 'Your Username',
            'required': ''
        })
        self.fields['password1'].widget.attrs.update({
            'placeholder': 'Your Password',
            'required': ''
        })
        self.fields['password2'].widget.attrs.update({
            'placeholder': 'Your Password',
            'required': ''
        })
        self.fields['first_name'].widget.attrs.update({
            'placeholder': 'Your Firstname',
            'required': ''
        })
        self.fields['last_name'].widget.attrs.update({
            'placeholder': 'Your Lastname',
            'required': ''
        })
        self.fields['email'].widget.attrs.update({
            'placeholder': 'Your Email',
            'required': ''
        })
    class Meta:
        model = User
        fields = ["username", "first_name", "last_name",
                  "email", "password1", "password2"]
class fCreatePost(forms.Form):
    title = forms.CharField(widget= forms.Textarea(attrs={"rows":2}))
    description = forms.CharField(widget= forms.Textarea(attrs={"rows":3}))
    body = forms.CharField(widget= forms.Textarea(attrs={"rows":8}))
    class Meta:
        model = mCreatePost
        exclude = ('user',)
