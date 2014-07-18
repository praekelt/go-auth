""" An oauthlib.oauth2 request valditator for Vumi Go.
"""

from oauthlib.oauth2 import RequestValidator, WebApplicationServer
from twisted.internet.defer import inlineCallbacks, returnValue


class StaticAuthValidator(RequestValidator):
    """ An oauthlib.oauth2 request validator.

    A validator built on top of a dictionary of access tokens.

    :param dict auth_store:
        The authentication store, a dictionary mapping access
        tokens to credentials.

    Example auth_store::

       {
           "ac3sst0k3n": {
               "client_id": "cl13nt51d",
               "scopes": ["scope1", "scope2"],
           },
       }
    """

    def __init__(self, auth_store=None):
        if auth_store is None:
            auth_store = {}
        self.auth_store = auth_store

    @inlineCallbacks
    def validate_bearer_token(self, token, scopes, request):
        stored_token = yield self._backend.retrieve_access_token(
            request.client_id)
        if stored_token is None:
            returnValue(False)
        if stored_token['access_token'] != token:
            returnValue(False)
        stored_scopes = stored_token['scopes'].split()
        available_scopes = set(stored_scopes) & set(scopes or ['foo'])
        # validate as true if any scopes are available
        returnValue(bool(available_scopes))

    def save_bearer_token(self, token, request, *args, **kw):
        return self._backend.store_access_token(request.client_id, token)

    def validate_client_id(self, client_id, request, *args, **kwargs):
        # Simple validity check, does client exist? Not banned?
        request.client_id = client_id

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        pass

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # The redirect used if none has been supplied.
        # Prefer your clients to pre register a redirect uri rather than
        # supplying one on each authorization request.
        pass

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        pass

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        pass

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        pass


def static_web_authenticator(auth_store):
    """ Return a Vumi Go static web authenticator.
    """
    validator = StaticAuthValidator(auth_store)
    authenticator = WebApplicationServer(validator)
    return authenticator
