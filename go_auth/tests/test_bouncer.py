""" Tests for go_auth.bouncer.
"""

import yaml

from twisted.internet.defer import inlineCallbacks
from twisted.trial.unittest import TestCase

from go_api.cyclone.helpers import AppHelper

from go_auth.bouncer import Bouncer


class TestBouncer(TestCase):
    def setUp(self):
        self.api = self.mk_api()
        self.auth_store = self.api.auth_store
        self.app_helper = AppHelper(app=self.api)

    def mk_config(self, config_dict):
        tempfile = self.mktemp()
        with open(tempfile, 'wb') as fp:
            yaml.safe_dump(config_dict, fp)
        return tempfile

    def mk_api(self):
        configfile = self.mk_config({
            "auth_store": {
                "access-1": {
                    "owner_id": "owner-1",
                    "client_id": "client-1",
                    "scopes": ["scope-a", "scope-b"],
                },
            },
        })
        return Bouncer(configfile)

    def assert_headers(self, resp, headers):
        for key, value in sorted(headers.items()):
            self.assertEqual(resp.headers.getRawHeaders(key), value)

    @inlineCallbacks
    def assert_body(self, resp, body):
        self.assertEqual((yield resp.text()), body)

    @inlineCallbacks
    def assert_authorized(self, resp):
        self.assertEqual(resp.code, 200)
        self.assert_headers(resp, {
            "X-Owner-ID": ["owner-1"],
            "X-Client-ID": ["client-1"],
            "X-Scopes": ["scope-a scope-b"],
        })
        yield self.assert_body(resp, (
            "Authenticated client 'client-1' with scopes:"
            " ['scope-a', 'scope-b'].\n"))

    @inlineCallbacks
    def assert_unauthorized(self, resp):
        self.assertEqual(resp.code, 401)
        self.assert_headers(resp, {
            "X-Owner-ID": None,
            "X-Client-ID": None,
            "X-Scopes": None,
        })
        yield self.assert_body(resp, (
            "<html><title>401: Unauthorized</title><body>401:"
            " Unauthorized</body></html>"))

    @inlineCallbacks
    def assert_forbidden(self, resp):
        self.assertEqual(resp.code, 403)
        self.assert_headers(resp, {
            "X-Owner-ID": None,
            "X-Client-ID": None,
            "X-Scopes": None,
        })
        yield self.assert_body(resp, (
            "<html><title>403: Forbidden</title><body>403:"
            " Forbidden</body></html>"))

    @inlineCallbacks
    def test_valid_credentials_in_query(self):
        resp = yield self.app_helper.get('/foo/?access_token=access-1')
        yield self.assert_authorized(resp)

    @inlineCallbacks
    def test_invalid_credentials_in_query(self):
        resp = yield self.app_helper.get('/foo/?access_token=unknown-1')
        yield self.assert_forbidden(resp)

    @inlineCallbacks
    def test_valid_credentials_in_headers(self):
        resp = yield self.app_helper.get('/foo/', headers={
            'Authorization': 'Bearer access-1',
        })
        yield self.assert_authorized(resp)

    @inlineCallbacks
    def test_invalid_credentials_in_headers(self):
        resp = yield self.app_helper.get('/foo/', headers={
            'Authorization': 'Bearer unknown-1',
        })
        yield self.assert_forbidden(resp)

    @inlineCallbacks
    def test_no_credentials(self):
        resp = yield self.app_helper.get('/foo/')
        yield self.assert_unauthorized(resp)
