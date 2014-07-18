""" Tests for go_auth.validator.
"""

from oauthlib.oauth2 import RequestValidator, WebApplicationServer
from oauthlib.common import Request, generate_token
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

    def mk_cred(self, owner_id="owner-1", client_id="client-1",
                access_token=None, scopes=("scope-a", "scope-b")):
        if access_token is None:
            access_token = generate_token()
        self.auth_store[access_token] = {
            "owner_id": owner_id,
            "client_id": client_id,
            "scopes": list(scopes),
        }
        return owner_id, client_id, access_token

    def mk_request(self, client_id):
        return Request("http://example.com/?client_id=%s" % (client_id,))

    def test_subclasses_request_validator(self):
        self.assertTrue(isinstance(self.validator, RequestValidator))

    def test_valid_credentials_in_query(self):
        owner_id, client_id, access_token = self.mk_cred()
        uri = "http://example.com/?access_token=%s" % access_token
        valid, request = self.auth.verify_request(
            uri, http_method="GET", headers={}, scopes=None)
        self.assertEqual(valid, True)
        self.assertEqual(request.token, access_token)
        self.assertEqual(request.owner_id, owner_id)
        self.assertEqual(request.client_id, client_id)
        self.assertEqual(request.scopes, ["scope-a", "scope-b"])

    def test_valid_credentials_in_headers(self):
        owner_id, client_id, access_token = self.mk_cred()
        uri = "http://example.com/"
        headers = {
            "Authorization": "Bearer %s" % (access_token,),
        }
        valid, request = self.auth.verify_request(
            uri, http_method="GET", headers=headers, scopes=None)
        self.assertEqual(valid, True)
        self.assertEqual(request.token, access_token)
        self.assertEqual(request.owner_id, owner_id)
        self.assertEqual(request.client_id, client_id)
        self.assertEqual(request.scopes, ["scope-a", "scope-b"])
