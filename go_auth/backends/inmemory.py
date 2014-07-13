"""
In-memory authorization store.
"""

from twisted.internet.defer import Deferred
from zope.interface import implementer

from .interfaces import IAuthBackend


def defer_async(value, reactor=None):
    if reactor is None:
        from twisted.internet import reactor
    d = Deferred()
    reactor.callLater(0, lambda: d.callback(value))
    return d


@implementer(IAuthBackend)
class InMemoryAuthBackend(object):
    """
    Simple backend that stores authorization codes and access tokens
    in memory.
    """
    def __init__(self, reactor=None):
        self.reactor = reactor
        self._access_tokens = {}

    def _defer(self, value):
        """
        Return a Deferred that is fired asynchronously.
        """
        return defer_async(value, self.reactor)

    def get_access_token(self, client_id):
        token = self._access_tokens.get(client_id)
        return self._defer(token)

    def save_access_token(self, client_id, token):
        self._access_tokens[client_id] = token
        return self._defer(None)
