from twisted.internet.task import Clock
from twisted.trial.unittest import TestCase
from zope.interface.verify import verifyObject

from go_auth.backends.interfaces import IAuthBackend
from go_auth.backends.inmemory import defer_async, InMemoryAuthBackend


class TestInMemoryMisc(TestCase):
    def test_defer_async(self):
        clock = Clock()
        d = defer_async('foo', reactor=clock)
        self.assertEqual(d.called, False)
        clock.advance(0)
        self.assertEqual(d.called, True)
        self.assertEqual(d.result, 'foo')


class TestInMemoryAuthBackend(TestCase):
    def setUp(self):
        self.clock = Clock()
        self.auth = InMemoryAuthBackend(reactor=self.clock)

    def assert_result(self, d, result):
        self.assertEqual(d.called, False)
        self.clock.advance(0)
        self.assertEqual(d.called, True)
        self.assertEqual(d.result, result)

    def test_provides_auth_backend(self):
        verifyObject(IAuthBackend, self.auth)

    def test_retrieve_missing_access_token(self):
        d = self.auth.retrieve_access_token('client-id')
        self.assert_result(d, None)

    def test_retrieve_access_token(self):
        token = object()
        self.auth._access_tokens['client-id'] = token
        d = self.auth.retrieve_access_token('client-id')
        self.assert_result(d, token)

    def test_store_access_token(self):
        token = object()
        d = self.auth.store_access_token('client-id', token)
        self.assert_result(d, None)
        self.assertEqual(self.auth._access_tokens, {
            "client-id": token,
        })

    def test_store_retrieve_access_token(self):
        token = object()
        d = self.auth.store_access_token('client-id', token)
        self.assert_result(d, None)
        d = self.auth.retrieve_access_token('client-id')
        self.assert_result(d, token)
