""" Tests for go_auth.bouncer.
"""

import yaml

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.trial.unittest import TestCase

from go_api.cyclone.helpers import AppHelper, MockHttpServer

from go_auth.bouncer import Bouncer, Proxier


def mk_config(tempfile, config_dict):
    with open(tempfile, 'wb') as fp:
        yaml.safe_dump(config_dict, fp)
    return tempfile


def mk_bouncer_config(tempfile, **kw):
    config_dict = {
        "auth_store": {
            "access-1": {
                "owner_id": "owner-1",
                "client_id": "client-1",
                "scopes": ["scope-a", "scope-b"],
            },
        }
    }
    config_dict.update(kw)
    return mk_config(tempfile, config_dict)


class TestBouncer(TestCase):
    def setUp(self):
        self.api = Bouncer(mk_bouncer_config(self.mktemp()))
        self.auth_store = self.api.auth_store
        self.app_helper = AppHelper(app=self.api)

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


class TestProxier(TestCase):
    def setUp(self):
        self.cleanups = []

    @inlineCallbacks
    def tearDown(self):
        for fn in reversed(self.cleanups):
            yield fn()

    @inlineCallbacks
    def mk_server(self, handler=None):
        server = MockHttpServer(handler)
        yield server.start()

        self.cleanups.append(server.stop)
        returnValue(server)

    @inlineCallbacks
    def test_proxy_response(self):
        server = yield self.mk_server(lambda _: "bar")

        config = mk_bouncer_config(self.mktemp(), proxy_url=server.url)
        helper = AppHelper(app=Proxier(config))

        resp = yield helper.get('/foo/', headers={
            'Authorization': 'Bearer access-1'
        })

        self.assertEqual((yield resp.text()), "bar")
