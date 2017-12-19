# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.core.urlresolvers import reverse

from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from django.core import mail

from .models import CustomUser, Team, Membership, VerificationToken
from rest_framework.authtoken.models import Token
from uuid import uuid4


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
		self.token = Token.objects.create(user=self.user)
		
	def tearDown(self):
		Token.objects.filter(user=self.user).delete()  #for the case of logout test since token object can be deleted before
		self.user.delete()
		self.client.credentials()  #clean credentials

	def test_login(self):
		responce = self.login(self.email, self.password)
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

	def test_reset_password(self):
		# Initiation
		url_init = reverse('reset password')
		responce = self.client.post(url_init, {'email': self.email})
		user = CustomUser.objects.get(email=self.email)
		code = user.password_reset_code
		self.assertEquals(responce.status_code, 200)
		self.assertTrue(code)

		# unauthorised change 
		url_set = reverse('set password')
		new_pass = 'N3w_p@$$word'
		# wrong data
		responce = self.client.post(url_set, {'email': 'a@a.com', 'password': new_pass, 'code': code})  # email
		self.assertEquals(responce.status_code, 400)
		responce = self.client.post(url_set, {'email': self.email, 'password': new_pass, 'code': uuid4().hex})  # code
		self.assertEquals(responce.status_code, 403)
		user = CustomUser.objects.get(email=self.email)
		self.assertTrue(user.password_reset_code)

		responce = self.client.post(url_set, {'email': self.email, 'password': new_pass, 'code': code})
		user = CustomUser.objects.get(email=self.email)
		token = Token.objects.filter(user=self.user).first()

		self.assertEquals(responce.status_code, 202)
		self.assertFalse(user.password_reset_code)
		self.assertFalse(token)  # there is no possibility to access app after token

		responce = self.login(self.email, new_pass)  #try to login with new credentials
		self.assertEquals(responce.status_code, 200)

	def test_change_password(self):
		url_set = reverse('set password')
		new_pass = 'N3w_p@$$word'
		self.user.password_reset_initiate()  # changing a password should remove a password reset code
		token = Token.objects.get(user=self.user)
		self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
		self.assertTrue(self.user.password_reset_code)

		responce = self.client.post(url_set, {'password': new_pass})

		user = CustomUser.objects.get(email=self.email)
		token = Token.objects.filter(user=self.user).first()

		self.assertTrue(user.check_password(new_pass))
		self.assertEquals(responce.status_code, 202)
		self.assertFalse(user.password_reset_code)
		self.assertFalse(token)  # there is no possibility to access app with old token

	def test_verify_email(self):
		v_token = VerificationToken.objects.get(user=self.user)
		url = reverse('verify_email')
		responce = self.client.post(url, {'code': v_token.code.hex})

		user = CustomUser.objects.get(email=self.email)
		token = VerificationToken.objects.filter(user=user).first()
		
		self.assertTrue(user.email_verified)
		self.assertEquals(responce.status_code, 202)
		self.assertFalse(token) 

	def login(self, email, password):
		self.client.credentials() #cleaning client credentials before login
		url_login = reverse('login')
		responce = self.client.post(url_login, {'email': email, 'password': password})
		return responce


