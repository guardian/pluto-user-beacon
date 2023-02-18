import datetime
import os
from unittest.mock import patch
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
    def test_load_public_key(self):
        public_key = self.jwt_auth.load_public_key()
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

    @override_settings(JWT_CERTIFICATE_PATH='http://example.com/cert')
    @patch('userbeacon.jwt_auth_backend.Request')
    def test_authenticate_with_remote_certificate(self, mock_request):
        mock_response = mock_request.get.return_value
        mock_response.json.return_value = {
            "keys": [
                {
                    "kid": "1234",
                    "x5c": ["MIIDETCCAfkCFFuaV9SqRhz6PE12Jv40vjEOcg25MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjMwMjE4MTAzNjA4WhcNMjQwMjE4MTAzNjA4WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvcw4cRhAPtp+z/Imi7tiXxRvf+yQ3bzbQBeRe2YLC9IgeN5n5wS6PSBi+HJFRNKEbnZKWl5wOPiWmgpIdpPmYq98EF/cDhs+re5ZT7GG0/+3wjFLE/p1q+Mb3/CgK8DxhzNblGS6SSZ6c24thg9A4Xu8HRvVaRn+K3zcfYNV8a2cZ2AUxAHdPov1KQ/BVVhwB4qmPaBfksvNFxi/X0nS74pUW1Czs64xNpRXT7EcWS9TL3sUEfzf6M1SV6urGy0zhDP5t4dppJ6AUDX1ytUiMccJ1PzNRnOvZPs2ogPBB6Tep/e08VUwKecAO6e7/BsWIW5fWuHME+c6LoxKnh3V/wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQApBjYWIw1P51Ei6zRwP+DVDsLITaKrPyhtl4fSAoUqT27De/AJovtOyP5zxvhxfEQQqVCKe0o4IGgT6yHw0I0itV8X2X1EQEJvXkYVbhBPHsfa83YYXT0vqyXINpdRxTbKm6+lWwD71Z34dOmgQmr5bQLYzF2XFnGIBx62uZThsredjSEV32QChrvZyik/elsTFBA0eZqksPkEaXalKY1BOYx8PKCskVnwc+Od0EW5/RhEirTb2jNUMbDTtmESp5SBAT/YwZ77OBiJsqHDtlUckntnhjJTEa1LjrzKzMKNU3wtQpZ6hJUGI9VUMI3IkhYTc+RKG2c6Lu8FlNXi3xJu"],
                }
            ]
        }
        mock_response.status_code = 200
        user_model = self.jwt_auth.authenticate(None, token=self.token)
        self.assertIsInstance(user_model, User)
        self.assertEqual(user_model.username, 'johndoe')
        self.assertEqual(user_model.first_name, 'John')
        self.assertEqual(user_model.last_name, 'Doe')
        self.assertEqual(user_model.email, 'john.doe@example.com')
        self.assertTrue(user_model.is_staff)
        self.assertTrue(user_model.is_active)
        self.assertTrue(user_model.is_superuser)
        

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
