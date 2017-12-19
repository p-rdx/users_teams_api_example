# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.core.urlresolvers import reverse

from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from django.core import mail

from .models import CustomUser, Team, Membership, VerificationToken
from rest_framework.authtoken.models import Token


class UserRegistrationTestCase(APITestCase):
	def setUp(self):
		self.email = 'test@case.com'
		self.first_name = 'f'
		self.last_name = 'l'
		self.password = 'P@ssw0rd'
		credentials = {'email': self.email, 'first_name': self.first_name, 'last_name': self.last_name, 'password': self.password,}
		team = Team.objects.create(name='team_name')
		su = CustomUser.objects.create_superuser(email='super@...', password='password')
		Membership.objects.create(user=su, team=team)

	def tearDown(self):
		Membership.objects.all().delete()
		CustomUser.objects.all().delete()
		Team.objects.all().delete()


	def test_register_user(self): 
		url = reverse('register')
		responce = self.client.post(url, {'email': self.email, 'first_name': self.first_name, 
			'last_name': self.last_name, 'password': self.password,})
		self.assertEqual(responce.status_code, 201)
		self.assertEqual(responce.data['email'], self.email)
		user = CustomUser.objects.get(email=self.email)
		self.assertTrue(isinstance(user, CustomUser))
		

	def test_register_via_invitation(self):
		url = reverse('register')
		inv = Membership.objects.first()
		responce = self.client.post(url, {'email': self.email, 'first_name': self.first_name, 
			'last_name': self.last_name, 'password': self.password, 'invitation': inv.code})

		user = CustomUser.objects.get(email=self.email)
		self.assertTrue(user)
		member = Membership.objects.filter(user=user).first()
		self.assertEqual(member.team, inv.team)

	def test_verify_email(self):
		url_reg = reverse('register')
		responce = self.client.post(url_reg, {'email': self.email, 'password': self.password,})

		user = CustomUser.objects.get(email=self.email)
		self.assertFalse(user.email_verified)

		verification = VerificationToken.objects.filter(user=user).first()
		self.assertTrue(verification)

		url_verify = reverse('verify_email')
		responce = self.client.post(url_verify, {'code': verification.code.hex})
		self.assertEqual(responce.status_code, 202)

		user = CustomUser.objects.get(email=self.email)
		self.assertTrue(user.email_verified)
		self.assertFalse(VerificationToken.objects.filter(user=user).exists())


class UserTestCase(APITestCase):
	def setUp(self):
		self.email = 'test@case.com'
		self.password = 'P@ssw0rd'
		self.user = CustomUser.objects.create_user(self.email, self.password)
		Token.objects.create(user=self.user)

	def tearDown(self):
		Token.objects.filter(user=self.user).delete()  #for the case of logout test since token object can be deleted before
		self.user.delete()

	def test_login(self):
		url_login = reverse('login')
		responce = self.client.post(url_login, {'email': self.email, 'password': self.password})
		token = Token.objects.get(user=self.user)
		self.assertEquals(responce.status_code, 200)
		self.assertEquals(token.key, responce.data['key'])

	def test_logout(self):
		url_logout = reverse('logout')
		token = Token.objects.get(user=self.user)
		self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
		responce = self.client.post(url_logout)
		self.assertEqual(responce.status_code, 200)
		self.assertFalse(Token.objects.filter(user=self.user).exists())
