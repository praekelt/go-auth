""" Bouncer for handling authentication on behalf of an API.

When an HTTP request is directed to an API, a proxy (e.g. nginx) redirects the
request to this service, which then returns either a 200 response
(authentication accepted) or a 401 response (authentication required). If a
200 response is received, the proxy then forwards the original request to the
API endpoint.

This bouncer returns the following additional headers which the proxy should
add to the original request:

* ``X-Owner-ID``:
    An ID for the resource owner.
* ``X-Scopes``:
    A space separated list of scopes the client has been given access to.

Example Nginx configuration::

    location /api/ {
        auth_request /auth/;
        auth_request_set $owner_id $upstream_http_x_owner_id;
        auth_request_set $scopes $upstream_http_x_scopes;
        proxy_pass http://localhost:8888/;
        proxy_set_header X-Owner-ID $owner_id;
        proxy_set_header X-Scopes $scopes;
    }

    location /auth/ {
        internal;
        proxy_pass http://localhost:8889/;
    }

Example scopes lists:

* ``contacts-read contacts-write``
* ``groups-read groups-write``
* ``messages-read messages-sensititve-read``
"""

import base64


from cyclone.web import Application, RequestHandler, HTTPError


class AuthHandler(RequestHandler):

    def raise_unauthorized(self, reason):
            self.set_header("WWW-Authenticate", 'Basic realm="Vumi Go"')
            raise HTTPError(401, reason)

    def check_credentials(self, username, password):
        if password == "passx":
            return True
        return False

    def check_authentication(self):
        auth = self.request.headers.get('Authorization')
        if auth is None:
            self.raise_unauthorized("Not authenticated")
        auth_type, _, raw_auth_data = auth.partition(" ")
        if auth_type != "Basic":
            self.raise_unauthorized("Only basic authentication supported")
        try:
            auth_data = base64.decodestring(raw_auth_data)
        except:
            self.raise_unauthorized("Invalid authentication data")
        username, _, password = auth_data.partition(":")
        if not self.check_credentials(username, password):
            self.raise_unauthorized("Invalid credentials")
        return username

    def get(self, *args, **kw):
        username = self.check_authentication()
        self.set_header("X-Owner-ID", username)
        self.write("Authenticated as %r.\n" % (username,))


class AuthServer(Application):
    """
    Go authentication service.
    """

    def __init__(self, **settings):
        routes = [
            (".*", AuthHandler),
        ]
        Application.__init__(self, routes, **settings)
