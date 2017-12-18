# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from rest_framework.response import Response
from rest_framework.authtoken.models import Token

from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext, ugettext_lazy as _
from django.conf import settings
from django.core import mail

from .models import CustomUser, Team, InvitationLink, VerificationToken
from .serializers import (LoginSerializer, TokenSerializer, CustomUserSerializer,
                          PasswordResetInitSerializer, PasswordResetSerializer,
                          PasswordResetExecSerializer, TeamSerializer, 
                          InvitationSerializer, MakeInvitationSerializer,
                          VerifyEmailSerializer, UserDetailSerializer)


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
            serializer = self.response_serializer(instance=token, 
                              context={'request': request})
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


class UserDetailsView(RetrieveUpdateAPIView):
    """
    User details

    Allows GET, PUT, POST

    returns user details
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = UserDetailSerializer
    
    def get_object(self):
        return self.request.user


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
            {'detail': _('Password reset has been initiated.')},
            status=status.HTTP_200_OK
            )


class PasswordResetView(PasswordResetGenericView):
    """
    Resets a password using password reset code (not autenticated)
    or without code (autenticated)

    recieves email, new password and password reset code

    returns success/error
    """    
    def get_serializer_class(self):
    	user = self.request.user
        if user and user.is_authenticated:
            return PasswordResetSerializer
        return PasswordResetExecSerializer

    def on_post_action(self, serializer):
        user = self.request.user
        if user and user.is_authenticated:
            user.set_password(serializer.validated_data['password'])
            user.save()
        else:
            user = serializer.validated_data['user']
            code = user.password_reset_code
            if serializer.validated_data['code'] == code:
                user.set_password(serializer.validated_data['password'])
                user.save()
            else:
                return Response(
                    {'detail': _('Password reset code is incorrect')}, 
                    status=status.HTTP_403_FORBIDDEN
                    )
        return Response(
                    {'detail': _('Password was sucessfully changed.')}, 
                    status=status.HTTP_202_ACCEPTED
                    )


class RegisterView(GenericAPIView):
    """
    Registers new users

    Recieves email, password (required), first name, last name, invitation code (optional)

    returns new user params
    """
    permission_classes = (AllowAny,)
    serializer_class = CustomUserSerializer
    output_serializer = UserDetailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.create(serializer.validated_data)
        return Response(self.output_serializer(instance=user).data, status=status.HTTP_201_CREATED)


class MakeInvitationLink(GenericAPIView):
    """
    View for creating an invitation links and sending them to recipients,
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
            with mail.get_connection() as connection:
                mail.EmailMessage(
                    'Join our nice app', 
                    'Your invitation code is {}'.format(invitation.code), 
                    settings.EMAIL_FROM, 
                    [email,],
                    connection=connection,
                ).send()  # ToDo abstract with email templates

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

    Recieves token, verifies email, deletes token

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


class RetrieveCodesView(GenericAPIView):
    """
    Debug only view

    returns email verification code or None
    and password reset code or None
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        if settings.DEBUG:
            details = dict()
            user = request.user
            if not user.email_verified:
                token = VerificationToken.objects.get(user=user)
                details['email_code'] = token.code
            else:
                details['email_code'] = None
            if user.password_reset_code:
                details['password_reset_code'] = user.password_reset_code
            else:
                details['password_reset_code'] = None
            return Response(
                    details, 
                    status=status.HTTP_200_OK
                    )
        else:
            return Responce({}, status.HTTP_404_NOT_FOUND)

class APIRoot(GenericAPIView):
    """
    This demo api have such variants of usage:

	^api/login/			login
	^api/logout/		logout
	^api/userdetails/ 	view and change user details (auth)
	^api/reset/ 		initiate reset password
	^api/password/ 		change password with reset code or with auth
	^api/invite/ 		create an invitation link to a team (auth)
	^api/register/		register new user 
	^api/create_team/ 	create team (auth)
	^api/verify_email/ 	verify e-mail
	^api/retrieve_code/	!DEBUG=True! retrieve verification codes (auth)
    * (auth) - requires authorisation
    """
