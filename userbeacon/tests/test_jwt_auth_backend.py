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

    @override_settings(JWT_CERTIFICATE_PATH='userbeacon/tests/fixtures/test_cert.pem')
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
                    "x5c": ["MIIDETCCAfkCFB1XU7b3jnBoUijY9m21Y1Vjdfv6MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjMwMjE2MTM0NDM0WhcNMjQwMjE2MTM0NDM0WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt+Gbh1YIujYiUqe/uZA5Kb2IbOK3Pmx3uxlpFUBxS1H1V8jRiAMyGDgt6hmH6/ygR2lt1/EDlf8H5+ltwJnklW/1eOu5WvzySNynOtHx2nAUaozM2G4/qe1nlEMHjXMC9m7NkrJH39C9KmqweoC1DYXjOJ3UMQulS1woQu2dgoMNjm01amCYoVu1tbUZrl46OfaeZSXALkbG60gk8dSo7TykLvHqfEmR9w2RuT97OTwlUY6M480KEE3FwgDvCB4jEqMNYcuTvHIOFzUEHeWwZQlPe3jYdUfiG60tT7waTO23jCim52o9VGPJp7IWdIaInlLFp4OYPz0hJUJPVEt7uwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCc/w0k8e3M5GGp+MIcOktauDrPtVaku4QSnfPeR3wRSYmoV0ESu17N9vFxN9Q8ptfeVMzMCCro0UBGeYvaXHgrhKOV4OUlqj2L6C3+8mBTRHj+MqYDJ5AdEqA1/1tjrk1STSOf/RhKhvp7eKPxcypemgWECy8vvXww3e3LRKWySJToojI7c6GYs+aFqKQd4KIq2Ob77YSmG98Zp4q2NJRHGEAa/iEmkQjpPR8S2RF8X26EjRjjE+wpkmkQ2j/Hu0jy3mT0gAK0/IUsuKHFx5A2WpCnZMWigPhPLAzbGpVy+429JaVDIJsF+n3JtL9R6YcoJ6WC9T+mRfUD6IJRptsu"],
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
        