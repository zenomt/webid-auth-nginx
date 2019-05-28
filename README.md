WebID Authorization Server for nginx
====================================
This is a [WebID-OIDC][] authorization and [Web Access Contro][WAC] server,
intended to be used as an [nginx][] [authorization subrequest][auth-module]
server.

This server presents an `authcheck` HTTP API that is compatible with *nginx*'s
[ngx_http_auth_request_module][auth-module], but it could be adapted easily
to work in other environments. Additionally it provides endpoints and default
pages to allow a user to log in with their WebID-OIDC credentials.

The server can be used to provide authorization and access control to files
and HTTP APIs behind a reverse proxy such as *nginx*.

### Work in Progress

The server is currently incomplete. `acl:agentGroup` is not currently
implemented. [WebID Authorization Protocol][zenomt-auth] support is planned
but not yet available. See [TODO][TODO.md] for more information.

### Dependencies

The server is written in Python 2.7, and has a few depenencies beyond the
standard library. This project is a work in progress and it is likely that
future revisions will have additional dependencies.  Install the requirements
with

	$ pip install -r requirements.txt

Web Access Control
------------------
The server implements [Web Access Control][WAC] with a few modifications:

  - the `acl`, `foaf`, `solid`, and `vcard` prefixes are pre-defined
  - `acl:Read` permission is required for every directory from the base prefix
    on down to the location of the requested resource
  - `acl:Other` permission mode for any method that doesn't fall under
    `acl:Read`, `acl:Write`, or `acl:Append`
  - `acl:origin` objects can be URIs or string literals
  - `acl:origin` can be the special literal `"*"`, which matches all origins
  - `acl:app` for [application identifier][zenomt-auth] prefixes (only usable
    with [WebID Authorization Protocol][zenomt-auth] bearer tokens, not yet
    implemented)

The permission modes are required to satisfy the following accesses:

  - `acl:Control` for any access to a resource whose URL path part ends
    with the acl suffix (by default `.acl`)

  - `acl:Read` for methods `OPTIONS`, `GET`, `HEAD`, `TRACE`, `PROPFIND`

  - `acl:Write` for methods `PUT`, `POST`, `DELETE`, `PATCH`, `PROPPATCH`,
    `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`

  - `acl:Append` for methods `PUT`, `POST`, `PATCH`, `PROPPATCH`, `MKCOL`,
    if `acl:Write` permission isn't granted

`auth.py`
---------
This is the server. By default it listens on IPv4 address `127.0.0.1` port
`8080` for HTTP requests sent directly or forwarded by *nginx*. Its one
required parameter is its own base URL. In addition, it must be provided with
a configuration file (by default in `data/config.json`). The configuration
file maps URI prefixes to local filesystem paths, where access control files
can be found. The local filesystem root path for a URI prefix can be collocated
with the actual files to be served, or can be in an independent directory
just for access control files.

In addition to `auth.py`'s configuration and base URL, *nginx* must be
configured to expose `auth.py` and use it for login and access control for
one or more locations.

The server exposes the following endpoints below its base URL:

  - `authcheck` -- The [authorization subrequest][auth-module] server
  - `login` -- Handler for the initial OIDC Provider entry page
  - `code` -- Handler for the OIDC `authorization_code` redirect
  - `refresh` -- Handler for the stale session reauthentication page
  - `logout` -- Handler for the "log out and try again with a different provider" page

In addition, the server provides the following default HTML pages (located
in the `www` directory) for logging in, refreshing, and forbidding access:

  - `401.html` -- The normal *Unauthorized* error page that prompts the user
    to log in
  - `401refresh.html` -- An error  page that causes the user's web browser
     to refresh the user's credentials
  - `403.html` -- An error page for when access to the resource is completely
    forbidden
  - `403logout.html` -- An error page for when access is forbidden, but where
    an alternate login might provide access

### `authcheck` API

### Configuration

Prepare `auth.py`'s configuration file, by default at `data/config.json`:

	{
		"locations": {
			"https://mike.example/wac/": "samples/root/"
		}
	}

Ensure that the root directory for each configured location contains a `.acl`
file (this is the case for `samples/root/`).

Run `auth.py` for its base URL `https://mike.example/auth/`, listening on `127.0.0.1`
port `8080`, and using `data/config.json` for its configuration file:

	$ python auth.py https://mike.example/auth/

Use the `-h` option to to see additional command-line configuration parameters.

Configure an *nginx* `proxy_pass` location for the `authcheck` endpoint. This
endpoint requires a different configuration than the others:

	server {
	    server_name mike.example;
	    ...

	    location /auth/authcheck {
	        internal;
	        auth_request off;
	        proxy_method GET;
	        proxy_pass_request_body off;
	        proxy_set_header Content-length "";
	        proxy_pass http://127.0.0.1:8080;
	        proxy_set_header X-Original-URI $scheme://$host:$server_port$request_uri;
	        proxy_set_header X-Forwarded-For $remote_addr;
	        proxy_set_header X-Original-Method $request_method;
	    }
	    ...

Configure an *nginx* `proxy_pass` location for the other `auth.py` endpoints and
HTML pages:

	    ...
	    location /auth/ {
	        auth_request off;
	        proxy_pass http://127.0.0.1:8080;
	        proxy_set_header X-Forwarded-For $remote_addr;
	        add_header Access-Control-Allow-Origin ""; # reset all add_headers
	    }
	    ...

If you don't already have a [CORS][] configuration and you want to support
Cross-Origin Resource Sharing, you can create a `cors.conf` file to make it
easier to add later on in different *nginx* configuration locations. For
example (remember that any `add_header` directive in an *nginx* `location`
or sub-`location` block clears all inherited `add_headers`):

	add_header Access-Control-Allow-Origin "$http_origin" always;
	add_header Access-Control-Expose-Headers "Age,Content-Range,ETag,Link,Location,Vary,WWW-Authenticate" always;

	if ($request_method = 'OPTIONS') {
	    add_header Access-Control-Allow-Origin "$http_origin";
	    add_header Access-Control-Allow-Headers "Cache-Control,If-Match,If-None-Match,If-Modified-Since,If-Unmodified-Since,If-Range,Range,Authorization,Content-Type";
	    add_header Access-Control-Allow-Methods "OPTIONS,HEAD,GET,PATCH,POST,PUT,DELETE,PROPFIND,PROPPATCH,MKCOL,COPY,MOVE,LOCK,UNLOCK";
	    add_header Access-Control-Max-Age 60;
	    return 204;
	}

Configure location(s) to use `auth.py` for authorization and access control, and to
use `auth.py`'s HTML pages for `401` and `403` responses:

	    location /wac {
	        auth_request /auth/authcheck;
	        auth_request_set $auth_mode $upstream_http_x_auth_mode;
	        error_page 401 /auth/401$auth_mode.html;
	        error_page 403 /auth/403$auth_mode.html;

	        include cors.conf; # if you created one as above
	    }



  [auth-module]: https://nginx.org/en/docs/http/ngx_http_auth_request_module.html
  [CORS]:        https://www.w3.org/TR/cors/
  [nginx]:       https://nginx.org/
  [solid]:       https://github.com/solid/solid
  [WAC]:         https://github.com/solid/web-access-control-spec
  [WebID-OIDC]:  https://github.com/solid/webid-oidc-spec
  [zenomt-auth]: https://github.com/zenomt/webid-auth-protocol
