# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import ugettext, ugettext_lazy as _

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
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

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
    password_reset_code = models.UUIDField(null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [] 

    email_verified = models.BooleanField(default=False, verbose_name='Validation passed')
    team = models.ManyToManyField('Team')

    objects = CustomUserManager()

    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'

    def __init__(self, *args, **kwargs):
        super(CustomUser, self).__init__(*args, **kwargs)
        self._email = copy(self.email)
        self._password = copy(self.password)

    def save(self, *args, **kwargs):
        if self.email != self._email:
            self.email_verified  = False
            self.send_validation_token(self)
        if self.password != self._password:
            self.password_reset_code = None
        super(CustomUser, self).save(*args, **kwargs)

    def generate_validation_token(self):
        if not self.email_verified :
            inp_string = '{}; {}'.format(self.email, self.pk)
            return md5(inp_string).hexdigest()
        else:
            return None

    def send_validation_token(self):
        """
        This method can be modified for other variants of token sending.
        """
        return self.generate_validation_token()

    def password_reset_initiate(self):
        self.password_reset_code = uuid4()
        self.save()
        return self.password_reset_code.hex


class Team(models.Model):
    name = models.CharField(max_length=150, unique=True)

    def __unicode__(self):
        return self.name


class InvitationLink(models.Model):
    """
    Since user can be linked to many teams, it is possible to create 
    an invitation link to each team where user participated
    """
    code = models.UUIDField(default=uuid4, unique=True)
    user = models.ForeignKey('CustomUser')
    team = models.ForeignKey('Team', null=True, blank=True)

    class Meta:
        unique_together = ('user', 'team')

