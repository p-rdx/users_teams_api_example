# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.core import mail
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import ugettext, ugettext_lazy as _
from django.conf import settings

from copy import copy
from hashlib import md5
from uuid import uuid4


class CustomUserManager(BaseUserManager):
    """
    Custom User manager with no username field
    """
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        user.generate_validation_token()
        return user

    def create_user(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('email_verified', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class CustomUser(AbstractUser):
    """
    Custom user class, authorisation by email address, 
    no username, many to many team relations
    """
    username = None
    email = models.EmailField(_('email address'), unique=True)
    password_reset_code = models.UUIDField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [] 

    email_verified = models.BooleanField(default=False, verbose_name='Validation passed')
    team = models.ManyToManyField('Team', blank=True, through='Membership')

    objects = CustomUserManager()

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'

    def __init__(self, *args, **kwargs):
        super(CustomUser, self).__init__(*args, **kwargs)
        self._email = copy(self.email)
        self._password = copy(self.password)

    def save(self, *args, **kwargs):
        send_token = False
        if self.email != self._email:
            self.email_verified  = False
            send_token = True
        if self.password != self._password:
            self.password_reset_code = None
        super(CustomUser, self).save(*args, **kwargs)
        if send_token:
            self.send_validation_token()

    def generate_validation_token(self):
        if not self.email_verified :
            existed = VerificationToken.objects.filter(user=self).delete()
            token = VerificationToken.objects.create(user=self)
            return token
        else:
            return None

    def send_validation_token(self):
        token = self.generate_validation_token()
        if token:
            with mail.get_connection() as connection:
                mail.EmailMessage(
                    'Please validate your email', 
                    'validation code is {}'.format(token.code), 
                    settings.EMAIL_FROM, 
                    [self.email,],
                    connection=connection,
                ).send()


    def password_reset_initiate(self):
        self.password_reset_code = uuid4()
        self.save()
        with mail.get_connection() as connection:
                mail.EmailMessage(
                    'Password reset code', 
                    'Password reset code is {}'.format(self.password_reset_code ), 
                    settings.EMAIL_FROM, 
                    [self.email,],
                    connection=connection,
                ).send()


class Team(models.Model):
    name = models.CharField(max_length=150, unique=True)

    def __unicode__(self):
        return self.name


class Membership(models.Model):
    """
    Since user can be linked to many teams, it is possible to create 
    an invitation link to each team where user participated
    """
    code = models.UUIDField(default=uuid4, unique=True)
    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE)
    team = models.ForeignKey('Team', null=True, blank=True, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('user', 'team')


class VerificationToken(models.Model):
    """
    model stores tokens, which are used to verify an e-mail
    """
    code = models.UUIDField(default=uuid4, unique=True)
    user = models.OneToOneField('CustomUser', on_delete=models.CASCADE)
