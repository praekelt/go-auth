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
                    "client_id": "client-1",
                    "scopes": ["scope-a", "scope-b"],
                },
            },
        })
        return Bouncer(configfile)

    @inlineCallbacks
    def test_valid_credentials_in_query(self):
        resp = yield self.app_helper.get('/foo/?access_token=access-1')
        self.assertEqual(resp.code, 200)

    @inlineCallbacks
    def test_invalid_credentials_in_query(self):
        resp = yield self.app_helper.get('/foo/?access_token=unknown-1')
        self.assertEqual(resp.code, 401)

    @inlineCallbacks
    def test_valid_credentials_in_headers(self):
        resp = yield self.app_helper.get('/foo/', headers={
            'Authorization': 'Bearer access-1',
        })
        self.assertEqual(resp.code, 200)

    @inlineCallbacks
    def test_invalid_credentials_in_headers(self):
        resp = yield self.app_helper.get('/foo/', headers={
            'Authorization': 'Bearer unknown-1',
        })
        self.assertEqual(resp.code, 401)
