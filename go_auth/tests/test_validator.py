""" Tests for go_auth.validator.
"""

from oauthlib.oauth2 import RequestValidator, WebApplicationServer
from oauthlib.common import Request
from twisted.trial.unittest import TestCase

from go_auth.validator import (
    StaticAuthValidator, static_web_authenticator)


class TestStaticWebAuthenticator(TestCase):
    def test_create(self):
        auth_store = {}
        auth = static_web_authenticator(auth_store)
        self.assertTrue(isinstance(auth, WebApplicationServer))
        self.assertTrue(
            isinstance(auth.request_validator, StaticAuthValidator))
        self.assertEqual(auth.request_validator.auth_store, auth_store)


class TestAuthValidator(TestCase):
    def setUp(self):
        self.auth_store = {}
        self.auth = static_web_authenticator(self.auth_store)
        self.validator = self.auth.request_validator

    def mk_token(self, access_token=None, scopes=None):
        if access_token is None:
            access_token = "12345"
        if scopes is None:
            scopes = ["laser", "periscope"]
        return {
            "access_token": access_token,
            "scopes": " ".join(scopes),
        }

    def mk_request(self, client_id):
        return Request("http://example.com/?client_id=%s" % (client_id,))

    def test_subclasses_request_validator(self):
        self.assertTrue(isinstance(self.validator, RequestValidator))
