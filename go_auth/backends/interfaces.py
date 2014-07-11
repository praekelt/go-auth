class MemoryAuthBackend(object):
    """ Simple backed that stores authorization codes and access tokens
        in memory.
    """
    def __init__(self, tokens):
        self._tokens = tokens

    def get_token(self, client_id):
        return self._tokens.get(client_id)

    def save_token(self, client_id, token):
        self._tokens[client_id] = token
