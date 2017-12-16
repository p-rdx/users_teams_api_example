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

from .models import CustomUser, Team
from .serializers import (LoginSerializer, TokenSerializer, CustomUserSerializer,
                          PasswordResetInitSerializer, PasswordResetExecSerializer)


class UserLoginView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer
    response_serializer = TokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            token, _ = Token.objects.get_or_create(user=user)
            serializer = self.response_serializer(instance=token, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)


class UserLogoutView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        try:
            request.user.auth_token.delete()
        except (AttributeError, ObjectDoesNotExist):
            pass

        return Response({"detail": _("Successfully logged out.")},
                        status=status.HTTP_200_OK)


class WhoamiView(APIView):
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
