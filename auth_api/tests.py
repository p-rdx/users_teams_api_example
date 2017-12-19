# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.core.urlresolvers import reverse

from rest_framework.test import APIClient, APITestCase
from rest_framework import status
from django.core import mail

from .models import CustomUser, Team, Membership, VerificationToken
from rest_framework.authtoken.models import Token
	

class SuperUserTestCase(APITestCase):
	su_email = 'super@user.com'
	su_password = 'P2ssw0rd'
	team_name = 'initial_team'
	is_abstract = True
		
	@classmethod
	def setUpClass(cls):
		team = Team.objects.create(name=cls.team_name)
		su = CustomUser.objects.create_superuser(email=cls.su_email, password=cls.su_password)
		Membership.objects.create(user=su, team=team)

	@classmethod
	def tearDownClass(cls):
		"""
		this allows to have a superuser available for all other tests, maybe it is wrong exploration
		"""
		pass

	def test_check_superuser(self):
		su = CustomUser.objects.get(email=self.su_email)
		team = Team.objects.get(name=self.team_name)
		inv = Membership.objects.get(user=su, team=team)

		self.assertTrue(su.email_verified)
		self.assertFalse(VerificationToken.objects.filter(user=su).exists())
		self.assertTrue(inv)

	def test_login_and_logout(self):
		url_login = reverse('login')
		url_logout = reverse('logout')
		user = CustomUser.objects.get(email=self.su_email)
		
		responce = self.client.post(url_login, {'email': self.su_email, 'password': self.su_password})
		token = Token.objects.get(user=user)
		self.assertEquals(responce.status_code, 200)
		self.assertEquals(token.key, responce.data['key'])

		self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
		responce = self.client.post(url_logout)
		token = Token.objects.filter(user=user).first()
		self.assertEqual(responce.status_code, 200)
		self.assertTrue(token is None)


class UserRegistrationTestCase(APITestCase):
	def setUp(self):
		self.email = 'test@case.com'
		self.first_name = 'f'
		self.last_name = 'l'
		self.password = 'P@ssw0rd'
		credentials = {'email': self.email, 'first_name': self.first_name, 'last_name': self.last_name, 'password': self.password,}

	def test_register_user(self): 
		url = reverse('register')
		responce = self.client.post(url, {'email': self.email, 'first_name': self.first_name, 
			'last_name': self.last_name, 'password': self.password,})
		self.assertEqual(responce.status_code, 201)
		self.assertEqual(responce.data['email'], self.email)
		user = CustomUser.objects.get(email=self.email)
		self.assertTrue(isinstance(user, CustomUser))
		self.assertFalse(user.email_verified)
		self.assertTrue(VerificationToken.objects.filter(user=user).exists())

	def test_register_via_invitation(self):
		url = reverse('register')
		inv = Membership.objects.first()
		responce = self.client.post(url, {'email': self.email, 'first_name': self.first_name, 
			'last_name': self.last_name, 'password': self.password, 'invitation': inv.code})

		user = CustomUser.objects.get(email=self.email)
		self.assertTrue(user)
		member = Membership.objects.filter(user=user).first()
		self.assertEqual(member.team, inv.team)
		