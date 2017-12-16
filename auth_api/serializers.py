from django.contrib.auth import authenticate
from django.utils.translation import ugettext, ugettext_lazy as _

from rest_framework import serializers, exceptions
from rest_framework.authtoken.models import Token

from .models import CustomUser, Team


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        user = None

        if email and password:
            user = authenticate(email=email, password=password)
        else:
            msg = _('Must include "email" and "password".')
            raise exceptions.ValidationError(msg)

        if user:
            if not user.is_active:
                msg = _('User account is disabled.')
                raise exceptions.ValidationError(msg)
        else:
            msg = _('Unable to log in with provided credentials.')
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        return attrs


class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ('key',)


class TeamSerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = ('name',)


class CustomUserSerializer(serializers.ModelSerializer):
    invitation = serializers.IntegerField(required=False)
    team = TeamSerializer(read_only=True, many=True)
    class Meta:
        model = CustomUser
        fields = ('email', 'email_verified', 'first_name', 'last_name', 'team', 'invitation', 'password')
        extra_kwargs = {'password': {'write_only': True}}
