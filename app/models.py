from dataclasses import fields
from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class mCreatePost(models.Model):
    title = models.CharField(max_length=100)
    description = models.CharField(max_length=255)
    body = models.TextField()
    author = models.ForeignKey(User, null=True ,on_delete=models.CASCADE)
    def __str__(self):
        return f"{self.id} - {self.title}"

