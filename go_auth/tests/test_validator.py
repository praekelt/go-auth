""" Tests for go_auth.validator.
"""

from oauthlib.oauth2 import RequestValidator, WebApplicationServer
from twisted.trial.unittest import TestCase

from go_auth.backends.inmemory import InMemoryAuthBackend
from go_auth.validator import AuthValidator, web_app_authenticator


class TestValidatorMisc(TestCase):
    def test_web_app_authenticator(self):
        auth = InMemoryAuthBackend()
        authenticator = web_app_authenticator(auth)
        self.assertTrue(isinstance(authenticator, WebApplicationServer))
        self.assertTrue(
            isinstance(authenticator.request_validator, AuthValidator))
        self.assertEqual(authenticator.request_validator._backend, auth)


class TestAuthValidator(TestCase):
    def setUp(self):
        self.auth = InMemoryAuthBackend()

    def test_subclasses_request_validator(self):
        validator = AuthValidator(self.auth)
        self.assertTrue(isinstance(validator, RequestValidator))

    def test_validate_bearer_token(self):
        validator = AuthValidator(self.auth)
        # TODO

    def test_save_bearer_token(self):
        validator = AuthValidator(self.auth)
        # TODO
