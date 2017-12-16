from django.contrib.auth import authenticate
from django.utils.translation import ugettext, ugettext_lazy as _

from rest_framework import serializers, exceptions
from rest_framework.authtoken.models import Token

from .models import CustomUser, Team, InvitationLink


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


class InvitationSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    team = TeamSerializer(read_only=True)
    class Meta:
        model = InvitationLink
        fields = ('code', 'user', 'team',)


class PasswordResetInitSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        email = attrs.get('email')
        try:
            user = CustomUser.objects.get(email__iexact=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError('User e-mail is invalid')

        attrs['user'] = user
        return attrs


class PasswordResetExecSerializer(PasswordResetInitSerializer):
    password = serializers.CharField(style={'input_type': 'password'}, required=True)
    code = serializers.UUIDField(required=True)


class MakeInvitationSerializer(serializers.Serializer):
    team = serializers.CharField(required=False)

    def validate(self, attrs):
        team_name = attrs.get('team')
        team = None
        if team_name:
            try:
                team = Team.objects.get(name__iexact=team_name)
            except Team.DoesNotExist:
                raise serializers.ValidationError("Team with this name doesn't exist")
            attrs['team'] = team
        return attrs

