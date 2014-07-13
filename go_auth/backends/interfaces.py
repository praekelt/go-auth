""" Interfaces for backends.
"""

from zope.interface import Interface


class IAuthBackend(Interface):
    """
    Backend for storing and retrieving authorization codes and
    access tokens.
    """

    def retrieve_access_token(client_id):
        """
        Retrieve the access token associated with the client_id.

        :param str client_id:
            The client id to retrieve the access token for.

        :return:
            The access token (possibly via a deferred) or
            None if no access token exists.
        """

    def store_access_token(client_id, token):
        """
        Save the access token for the associated client_id.

        :param str client_id:
            The client id the access token belongs to.
        :param token:
            The token to store.

        :return:
            A deferred that fires once the token is stored.
        """
