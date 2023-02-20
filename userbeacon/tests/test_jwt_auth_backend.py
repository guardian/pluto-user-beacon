import datetime
import json
import os
from unittest.mock import MagicMock, patch
from django.test import TestCase, override_settings
from django.contrib.auth.models import User
import jwt
from userbeacon.jwt_auth_backend import JwtAuth, JwtRestAuth


class JwtAuthTestCase(TestCase):
    def setUp(self):
        self.jwt_auth = JwtAuth()
        header = { 
            'alg': 'RS256',
            'typ': 'JWT',
            'kid': '1234'
}
        payload = {
            'sub': '1234567890',
            'first_name': 'John',
            'family_name': 'Doe',
            'iat': 1516239022,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # Expires in 1 hour
            'email': 'john.doe@example.com',
            'preferred_username': 'johndoe'
        }   
        private_key = open('userbeacon/tests/fixtures/private.key', 'r').read()
        self.token = jwt.encode(headers=header, payload=payload, key=private_key, algorithm='RS256')

    @override_settings(JWT_CERTIFICATE_PATH='userbeacon/tests/fixtures/certificate.crt')
    def test_load_local_public_key(self):
        public_key = self.jwt_auth.load_local_public_key()
        self.assertIsNotNone(public_key)

    def test_extract_username(self):
        claims = {'username': 'testuser'}
        username = self.jwt_auth._extract_username(claims)
        self.assertEqual(username, 'testuser')

        claims = {'preferred_username': 'testuser2'}
        username = self.jwt_auth._extract_username(claims)
        self.assertEqual(username, 'testuser2')

        claims = {}
        username = self.jwt_auth._extract_username(claims)
        self.assertIsNone(username)

    @override_settings(JWT_CERTIFICATE_PATH='userbeacon/tests/fixtures/certificate.crt')
    def test_authenticate_with_local_cert(self):
        user_model = self.jwt_auth.authenticate(None, token=self.token)
        self.assertIsInstance(user_model, User)
        self.assertEqual(user_model.username, 'johndoe')
        self.assertEqual(user_model.first_name, 'John')
        self.assertEqual(user_model.last_name, 'Doe')
        self.assertEqual(user_model.email, 'john.doe@example.com')
        self.assertTrue(user_model.is_staff)
        self.assertTrue(user_model.is_active)
        self.assertTrue(user_model.is_superuser)

    @override_settings(JWT_CERTIFICATE_PATH='https://example.com/cert.pem')
    @patch('userbeacon.jwt_auth_backend.jwt')
    def test_load_remote_public_key_with_valid_token(self, mock_jwt):
        mock_jwks_client = MagicMock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = MagicMock(key='public_key')
        mock_jwt.PyJWKClient.return_value = mock_jwks_client
        public_key = self.jwt_auth.load_remote_public_key('valid_token')
        self.assertEqual(public_key, 'public_key')
        mock_jwt.PyJWKClient.assert_called_once_with('https://example.com/cert.pem')
        mock_jwks_client.get_signing_key_from_jwt.assert_called_once_with('valid_token')

    @override_settings(JWT_CERTIFICATE_PATH='https://example.com/cert.pem')
    @patch('userbeacon.jwt_auth_backend.JwtAuth.load_remote_public_key')
    def test_authenticate_with_remote_public_key(self, mock_load_remote_public_key):
        expected_username = 'testuser'
        expected_first_name = 'Test'
        expected_last_name = 'User'
        expected_email = 'testuser@example.com'
        token = 'test_token'
        mock_public_key = MagicMock()
        mock_public_key.return_value = 'test_public_key'
        mock_load_remote_public_key.return_value = mock_public_key
        expected_user = {
            'username': expected_username,
            'first_name': expected_first_name,
            'family_name': expected_last_name,
            'email': expected_email,
            'is_staff': True,
            'is_active': True,
            'is_superuser': True,
        }

        mock_jwt_decode = MagicMock()
        mock_jwt_decode.return_value = expected_user
        with patch('jwt.decode', mock_jwt_decode):

            user = self.jwt_auth.authenticate(None, token=token)

            self.assertEqual(user.username, expected_username)
            self.assertEqual(user.first_name, expected_first_name)
            self.assertEqual(user.last_name, expected_last_name)
            self.assertEqual(user.email, expected_email)
            self.assertTrue(user.is_staff)
            self.assertTrue(user.is_active)
            self.assertTrue(user.is_superuser)

        # Assert that the load_remote_public_key method is called with the correct arguments
        mock_load_remote_public_key.assert_called_with(token)


class JwtRestAuthTestCase(TestCase):
    @override_settings(JWT_CERTIFICATE_PATH='userbeacon/tests/fixtures/certificate.crt')
    def test_authenticate(self):
        payload = {
            'sub': '1234567890',
            'first_name': 'John',
            'family_name': 'Doe',
            'iat': 1516239022,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # Expires in 1 hour
            'email': 'john.doe@example.com',
            'preferred_username': 'johndoe'
        }   
        private_key = open('userbeacon/tests/fixtures/private.key', 'r').read()
        token = jwt.encode(payload, private_key, algorithm='RS256')
        request = type('TestRequest', (object,), {
            'META': {
                'HTTP_AUTHORIZATION': f'Bearer {token}'
            }
        })
        jwt_rest_auth = JwtRestAuth()
        user_model, auth_type = jwt_rest_auth.authenticate(request)
        self.assertIsInstance(user_model, User)
        self.assertEqual(auth_type, 'jwt')
        self.assertEqual(user_model.username, 'johndoe')
        self.assertEqual(user_model.first_name, 'John')
        self.assertEqual(user_model.last_name, 'Doe')
        self.assertEqual(user_model.email, 'john.doe@example.com')
        self.assertTrue(user_model.is_superuser)