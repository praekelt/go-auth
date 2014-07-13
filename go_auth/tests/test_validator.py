""" Tests for go_auth.validator.
"""

from oauthlib.oauth2 import RequestValidator, WebApplicationServer
from oauthlib.common import Request
from twisted.internet.defer import inlineCallbacks
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
        validator = AuthValidator(self.auth)
        self.assertTrue(isinstance(validator, RequestValidator))

    @inlineCallbacks
    def test_validate_bearer_token_fails_no_token(self):
        validator = AuthValidator(self.auth)
        request = self.mk_request("client1")
        token = self.mk_token()
        self.assertEqual(
            (yield validator.validate_bearer_token(token, ["laser"], request)),
            False)

    @inlineCallbacks
    def test_validate_bearer_token_fails_mismatched_access_token(self):
        validator = AuthValidator(self.auth)
        request = self.mk_request("client1")
        token_good = self.mk_token()
        token_bad = self.mk_token(access_token=u"bad horse")
        yield self.auth.store_access_token("client1", token_good)
        self.assertEqual(
            (yield validator.validate_bearer_token(
                token_bad, ["laser"], request)),
            False)

    @inlineCallbacks
    def test_validate_bearer_token_fails_mismatched_scopes(self):
        validator = AuthValidator(self.auth)
        request = self.mk_request("client1")
        token = self.mk_token(scopes=["laser", "periscope"])
        yield self.auth.store_access_token("client1", token)
        self.assertEqual(
            (yield validator.validate_bearer_token(token, ["sith"], request)),
            False)

    @inlineCallbacks
    def test_validate_bearer_token_fails_no_scopes(self):
        validator = AuthValidator(self.auth)
        request = self.mk_request("client1")
        token = self.mk_token(scopes=["laser", "periscope"])
        yield self.auth.store_access_token("client1", token)
        self.assertEqual(
            (yield validator.validate_bearer_token(token, [], request)),
            False)

    @inlineCallbacks
    def test_validate_bearer_token_succeeds(self):
        validator = AuthValidator(self.auth)
        request = self.mk_request("client1")
        token = self.mk_token(scopes=["laser", "periscope"])
        yield self.auth.store_access_token("client1", token)
        self.assertEqual(
            (yield validator.validate_bearer_token(token, ["laser"], request)),
            True)

    @inlineCallbacks
    def test_save_bearer_token(self):
        validator = AuthValidator(self.auth)
        request = self.mk_request("client1")
        token = self.mk_token()
        self.assertEqual(
            (yield validator.save_bearer_token(token, request)),
            None)
        self.assertEqual(
            (yield self.auth.retrieve_access_token("client1")),
            token)
