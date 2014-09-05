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
        # this is the service that needs authentication
        auth_request /auth/;
        auth_request_set $owner_id $upstream_http_x_owner_id;
        auth_request_set $client_id $upstream_http_x_client_id;
        auth_request_set $scopes $upstream_http_x_scopes;
        proxy_pass http://localhost:8888/;
        proxy_set_header X-Owner-ID $owner_id;
        proxy_set_header X-Client-ID $client_id;
        proxy_set_header X-Scopes $scopes;
    }

    location /auth/ {
        # this is the bouncer
        internal;
        proxy_pass http://localhost:8889/;
    }

Example scopes lists:

* ``contacts-read contacts-write``
* ``groups-read groups-write``
* ``messages-read messages-sensititve-read``
"""

from urlparse import urljoin

from twisted.internet.defer import inlineCallbacks

from cyclone.web import (
    Application, RequestHandler, HTTPError, HTTPAuthenticationRequired)

import treq

from go_api.cyclone.handlers import read_yaml_config, HealthHandler

from go_auth.validator import static_web_authenticator


class BounceAuthHandler(RequestHandler):
    # NOTE: cyclone supports a `default` handler as opossed to specifying each
    # method type handler explicitly. The current version of cyclone available
    # on pypi (v1.1) does not support this though, thus the need for these
    # explicit handlers

    def initialize(self, auth, config):
        self.auth = auth
        self.config = config

    def raise_authorization_required(self, reason):
        raise HTTPAuthenticationRequired(
            log_message=reason, auth_type="Basic", realm="Vumi Go")

    def raise_denied(self, reason):
        raise HTTPError(403, reason=reason)

    def check_oauth(self):
        valid, request = self.auth.verify_request(
            self.request.uri, http_method=self.request.method,
            headers=self.request.headers, scopes=None)
        if request.token is None:
            self.raise_authorization_required("OAuth2 required.")
        if not valid:
            self.raise_denied("Auth failed.")
        if not request.owner_id:
            self.raise_denied("Invalid owner id.")
        if not request.client_id:
            self.raised_denied("Invalid client id.")
        if not request.scopes:
            self.raise_denied("Invalid scopes.")
        return (request.owner_id, request.client_id, request.scopes)

    def default(self, *args, **kw):
        owner_id, client_id, scopes = self.check_oauth()
        self.set_header("X-Owner-ID", owner_id)
        self.set_header("X-Client-ID", client_id)
        self.set_header("X-Scopes", " ".join(scopes))
        self.write("Authenticated client %r with scopes: %r.\n"
                   % (client_id, scopes))

    def head(self, *args, **kw):
        return self.default(*args, **kw)

    def get(self, *args, **kw):
        return self.default(*args, **kw)

    def post(self, *args, **kw):
        return self.default(*args, **kw)

    def put(self, *args, **kw):
        return self.default(*args, **kw)

    def patch(self, *args, **kw):
        return self.default(*args, **kw)

    def delete(self, *args, **kw):
        return self.default(*args, **kw)

    def options(self, *args, **kw):
        return self.default(*args, **kw)


class ProxyAuthHandler(BounceAuthHandler):

    @inlineCallbacks
    def default(self, *args, **kw):
        owner_id, client_id, scopes = self.check_oauth()
        headers = self.request.headers.copy()
        # treq adds a duplicate Content-Length header if we have one.
        headers.pop("Content-Length", None)
        headers["X-Owner-ID"] = owner_id
        headers["X-Client-ID"] = client_id
        headers["X-Scopes"] = " ".join(scopes)
        resp = yield treq.request(
            self.request.method, self.proxy_url(self.request.uri),
            headers=headers, data=self.request.body)
        self.set_status(resp.code)
        for header, items in resp.headers.getAllRawHeaders():
            # cyclone adds a duplicate Content-Encoding header if we have one.
            if header == "Content-Encoding":
                continue
            for item in items:
                self.add_header(header, item)
        body = yield resp.text()
        self.write(body)

    def proxy_url(self, url):
        return urljoin(self.config['proxy_url'], url)


class Bouncer(Application):
    """
    Go authentication bouncer service.
    """

    AUTH_CLASS = BounceAuthHandler

    def __init__(self, configfile, **settings):
        self.config = read_yaml_config(configfile)
        self.auth_store = self.config['auth_store']
        self.auth = static_web_authenticator(self.auth_store)

        kwargs = {
            "auth": self.auth,
            "config": self.config,
        }

        routes = [
            ("/health/", HealthHandler),
            (".*", self.AUTH_CLASS, kwargs),
        ]

        Application.__init__(self, routes, **settings)

    def log_request(self, handler):
        if getattr(handler, 'suppress_request_log', False):
            # The handler doesn't want to be logged, so we're done.
            return

        return Application.log_request(self, handler)


class Proxier(Bouncer):
    """
    Go authentication proxier service.
    """

    AUTH_CLASS = ProxyAuthHandler
