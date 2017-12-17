# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from rest_framework.response import Response
from rest_framework.authtoken.models import Token

from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext, ugettext_lazy as _

from .models import CustomUser, Team, InvitationLink
from .serializers import (LoginSerializer, TokenSerializer, CustomUserSerializer,
                          PasswordResetInitSerializer, PasswordResetExecSerializer,
                          TeamSerializer, InvitationSerializer, MakeInvitationSerializer,
                          VerifyEmailSerializer)


class UserLoginView(GenericAPIView):
    """
    Login view
    Recieves email and password
    returns auth token
    """
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer
    response_serializer = TokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            serializer = self.response_serializer(instance=token, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)


class UserLogoutView(APIView):
    """
    Logout, deletes auth token
    returns success/error
    """
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        try:
            request.user.auth_token.delete()
        except (AttributeError, ObjectDoesNotExist):
            pass

        return Response({"detail": _("Successfully logged out.")},
                        status=status.HTTP_200_OK)


class WhoamiView(APIView):
    """
    Info view, accepts only GET, require authentification
    Returns current logged user
    """
    permission_classes = (IsAuthenticated,)
    response_serializer = CustomUserSerializer

    def get(self, request, *args, **kwargs):
        user = request.user
        serializer = self.response_serializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PasswordResetGenericView(GenericAPIView):
    abstract = True
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self.on_post_action(serializer)


class PasswordResetInitView(PasswordResetGenericView):
    """
    Initiates a password reset function
    recieves e-mail
    returns success/error
    """
    serializer_class = PasswordResetInitSerializer

    def on_post_action(self, serializer):
        user = serializer.validated_data['user']
        code = user.password_reset_initiate()
        return Response(
            {'detail': _('Password reset has been initiated.'),
            'code': _(code)},                    # This should be changed to sending code by e-mail
            status=status.HTTP_200_OK
            )


class PasswordResetView(PasswordResetGenericView):
    """
    Resets a password using password reset code
    recieves email, new password and password reset code
    returns success/error
    """    
    serializer_class = PasswordResetExecSerializer

    def on_post_action(self, serializer):
        user = serializer.validated_data['user']
        code = user.password_reset_code
        if serializer.validated_data['code'] == code:
            user.set_password(serializer.validated_data['password'])
            user.save()
            return Response(
                {'detail': _('Password was sucessfully changed.')}, 
                status=status.HTTP_202_ACCEPTED
                )
        else:
            return Response(
                {'detail': _('Password reset code is incorrect')}, 
                status=status.HTTP_403_FORBIDDEN
                )

class RegisterView(GenericAPIView):
    """
    Registers new users
    Recieves email, password (required), first name, last name, invitation code (optional)
    returns new user params
    """
    permission_classes = (AllowAny,)
    serializer_class = CustomUserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.create(serializer.validated_data)
        return Response(self.serializer_class(instance=user).data, status=status.HTTP_200_OK)


class MakeInvitationLink(GenericAPIView):
    """
    View for creating an invitation links and sending them to recipients
    Requires authorisation
    Recieves team name and recipient email (both optional)
    returns invitation params
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = MakeInvitationSerializer
    response_serializer = InvitationSerializer

    def post(self, request, *args, **kwargs):
        user = request.user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        team = serializer.validated_data.get('team', None)
        email = serializer.validated_data.get('email', None)

        if team:
            if not user.team.filter(pk=team.pk).exists():
                return Response(
                {'detail': _('You can not invite to teams you are not participated in')}, 
                status=status.HTTP_403_FORBIDDEN
                )
        invitation, created = InvitationLink.objects.get_or_create(user=user, team=team)
        out_serializer = self.response_serializer(instance=invitation, context={'request': request})
        if email:
            pass  # place for sending the email to a person who you want to invite

        return Response(out_serializer.data, status=status.HTTP_200_OK)

class CreateTeamView(GenericAPIView):
    """
    Creates new team, requires authentification
    returns success/error
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = TeamSerializer

    def post(self, request, *args, **kwargs):
        user = request.user
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        team = serializer.create(serializer.validated_data)
        user.team.add(team)
        user.save()
        return Response(
            {'detail': _('New team was successfully created')}, 
            status=status.HTTP_202_ACCEPTED
            )


class VerifyEmailView(GenericAPIView):
	"""
	Verify email using verification token
	Recieves token
	verifies email, deletes token
	returns success/error
	"""
    permission_classes = (AllowAny,)
    serializer_class = VerifyEmailSerializer

    def post(self, request, *args, **kwargs):
    	serializer = self.serializer_class(data=request.data)
    	serializer.is_valid(raise_exception=True)
    	token = serializer.validated_data['token']
    	token.user.email_verified = True
    	token.user.save()
    	token.delete()
        return Response(
        	{'detail': _('E-mail was verified')},
        	status=status.HTTP_200_OK
        	)
