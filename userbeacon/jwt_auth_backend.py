import logging
import jwt
from django.contrib.auth.models import User
from django.conf import settings
from django.contrib.auth import PermissionDenied, authenticate
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import traceback
logger = logging.getLogger(__name__)


class JwtAuth(object):
    @staticmethod
    def load_public_key_from_cert():
        try:
            with open(settings.JWT_CERTIFICATE_PATH, "r") as certfile:
                cert_raw = certfile.read().encode("ASCII")
                cert = load_pem_x509_certificate(cert_raw, default_backend())
                return cert.public_key()
        except Exception as e:
            logger.error('Could not read certificate: ' + str(e))
            raise

    def __init__(self):
        self._public_key = self.load_public_key_from_cert()

    @staticmethod
    def _extract_username(claims):
        username = claims.get("username")   #adfs uses this one
        if username is None:
            username = claims.get("preferred_username") #keycloak uses this one
        if username is None:
            logger.warning("Could not get username from claims set, expect problems")
        return username

    def authenticate(self, request, **credentials):
        token = credentials.get("token", None)
        if token:
            logger.debug("JwtAuth got token {0}".format(token))
            try:
                decoded = jwt.decode(token,
                                     key=self._public_key,
                                     algorithms=["RS256"],
                                     audience=getattr(settings, "JWT_EXPECTED_AUDIENCE", None),
                                     issuer=getattr(settings, "JWT_EXPECTED_ISSUER", None))
                logger.debug("JwtAuth success")

                return User(
                    username=self._extract_username(decoded),
                    first_name=decoded.get("first_name"),
                    last_name=decoded.get("family_name"),
                    email=decoded.get("email"),
                    is_staff=True,
                    is_active=True,
                    is_superuser=True   #until we have groups added in to the JWT claim
                )
            except jwt.exceptions.DecodeError as e:
                logger.error("Could not decode provided JWT: {0}".format(e))
                raise PermissionDenied()
            except jwt.exceptions.ExpiredSignatureError:
                logger.error("Token signature has expired")
            except jwt.exceptions.InvalidAudienceError:
                logger.error("Token was for another audience: {0}".format())
            except Exception as e:
                logger.error("Unexpected error decoding JWT: {0}".format(traceback.format_exc(e)))
        raise PermissionDenied()

    def get_user(self, token):
        return self.authenticate(None, token=token)


class JwtRestAuth(BaseAuthentication):
    """
    this class is a REST-framework compatible authentication class
    which calls out to our authentication backend via django.authenticate
    """
    def authenticate(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", None)
        if isinstance(auth_header, str) and auth_header.startswith("Bearer "):
            try:
                user_model = authenticate(request, token=auth_header[7:])
                return user_model, "jwt"
            except PermissionDenied:
                raise AuthenticationFailed
        else:
            return None #authentication not attempted
