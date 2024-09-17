from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

class Admin3sManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

class Admin3s(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('developper', 'Developper'),
        ('admin', 'Admin'),
        ('supervisor', 'Supervisor'),
        ('devops', 'Devops'),
    ]

    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(max_length=254, unique=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='developper')
    is_active = models.BooleanField(default=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    objects = Admin3sManager()

    def __str__(self):
        return self.username

    

from django.conf import settings

class Project(models.Model):
    STATUS_CHOICES = [
        ('In Progress', 'In Progress'),
        ('Completed', 'Completed'),
        ('On Hold', 'On Hold'),
    ]

    name = models.CharField(max_length=100)
    description = models.TextField()
    github_url = models.URLField()
    languages = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE) 
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Pipeline(models.Model):
    name = models.CharField(max_length=100)
    jenkins_file = models.TextField()

    def __str__(self):
        return self.name


class Service(models.Model):
    nom = models.CharField(max_length=100)
    image = models.ImageField(upload_to='img/')
    url = models.URLField(max_length=200)
    role = models.CharField(max_length=50, choices=[
        ('admin', 'Admin'),
        ('developer', 'Developer'),
        ('devops', 'DevOps'),
        ('supervisor', 'Supervisor'),
    ])

    def __str__(self):
        return self.nom
