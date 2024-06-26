WebID Authorization Server for nginx
====================================
This is a [WebID-OIDC][] authorization and [Web Access Control][WAC] server,
intended to be used as an [nginx][] [authorization subrequest][auth-module]
server.

This server presents an `authcheck` HTTP API that is compatible with *nginx*'s
[ngx_http_auth_request_module][auth-module], but it could be adapted easily
to work in other environments. Additionally it provides endpoints and default
pages to allow a user to log in with their WebID-OIDC credentials.

The server provides a `webid-pop` HTTP endpoint that serves as the reference
implementation for the `token_pop_endpoint` API described in
[WebID HTTP Authorization Protocol][zenomt-auth].

The server can be used to provide authorization and access control to files
and HTTP APIs behind a reverse proxy such as *nginx*.

### Work in Progress

This is a work in progress. See [TODO](TODO.md) for what's On The List.

### Dependencies

The server is written in Python 2.7, and has a few depenencies beyond the
standard library. This project is a work in progress and it is likely that
future revisions will have additional dependencies.  Install the requirements
with

	$ pip install -r requirements.txt

Web Access Control
------------------
The server implements [Web Access Control][WAC] with several modifications:

  - The `acl:`, `foaf:`, `rdfs:`, `solid:`, and `vcard:` prefixes are pre-defined for convenience;
  - `acl:Search` permission is required for every directory from the base prefix
    down to the location of the requested resource (this permission is inferred for
    all if it doesn't appear anywhere in the access control file);
  - `acl:Read` permission in an ACL file also grants read for that ACL file;
  - `acl:Other` permission mode for any method that doesn't fall under
    `acl:Read`, `acl:Write`, or `acl:Append`;
  - Origins are handled differently:
    * There is always an effective Request Origin, which is either the origin of the
      [application identifier][zenomt-auth], or the `Origin` request header,
      or the origin of the target URI;
    * `acl:origin` objects can be URIs or string literals;
    * `acl:origin` can be the special literal `"*"`, which matches all origins;
    * `acl:origin` can be `</>`, which matches the target URI's origin;
  - `acl:app` for [application identifier][zenomt-auth] prefixes (only usable
    with [WebID Authorization Protocol][zenomt-auth] bearer tokens);
  - `acl:tag` for app tags/scopes. See [application tagging](#application-tagging)
    below for more information. This is only usable with bearer tokens.
  - `acl:default`'s value can now be an `xsd:boolean` (default `false`); any
    non-`false` value makes the `acl:Authorization` eligible for consideration
    when inherited;
  - `acl:accessTo` is not used and is ignored. Instead, use `acl:accessToClass` with the
    following classes:
    * `acl:Resource` - the class of all resources subject to WAC (the default if no
      class(es) is specified);
    * `acl:Container` - the class of all containers/directories;
    * `acl:Document` - the class of all non-container resources;
    * `acl:SubResource` - the class of all resources excluding the container
      whose Access Control Resource this is;
    * `acl:SubContainer` - the class of all containers excluding the one whose
      Access Control Resource this is.
  - `acl:excludeAgent` and `acl:excludeAgentGroup` predicates to exclude agent(s)
    from an `acl:Authorization` even if otherwise allowed;
  - `acl:excludeOrigin` predicate to exclude an effective request origin even if
    otherwise allowed;
  - `rdfs:seeAlso` (with subject being the Access Control Resource document URI) can be
    used to reference other access control files, in order to allow for reuse
    and composition of access control policies. Only local files are loaded
    (remote URIs are not loaded).  `rdfs:seeAlso` is not evaluated recursively
    (that is, any `rdfs:seeAlso`s in loaded policy sub-documents are not
    followed).  The merge of the primary access control graph and the graphs
    of those documents directly referenced from the primary is queried to
    make an access control determination.

For more information, see [`acl-changes.ttl`](acl-changes.ttl).


The following permission modes are required to satisfy the following accesses:

  - `acl:Search` on a directory/container for any resource in that container;
  - `acl:Control` for any access to a resource whose URL path part ends
    with the ACL suffix (by default `.acl`);
  - `acl:Read` for methods `OPTIONS`, `GET`, `QUERY`, `HEAD`, `TRACE`, `PROPFIND`,
    `SEARCH`;
  - `acl:Read` for the above read methods on an ACL resource if `acl:Control`
    isn't granted;
  - `acl:Write` for methods `PUT`, `POST`, `DELETE`, `PATCH`, `PROPPATCH`,
    `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`;
  - `acl:Append` for methods `PUT`, `POST`, `PATCH`, `PROPPATCH`, `MKCOL`,
    if `acl:Write` permission isn't granted.
  - `acl:Other` for any other methods.

### Application Tagging

The server implements a [proposed method][tags] for letting the user control
the scopes for which an application she is using has permission.

The resource owner/controller can specify one or more tag patterns (scopes)
for an `acl:Authorization` instead of an `acl:origin` or `acl:app`:

	# ACL for a container of chat messages, allowing
	# read for all authenticated users who are using
	# an app with a tag pattern that matches "Chat.Public".
	[]
	    a acl:Authorization;
	    acl:mode acl:Read;
	    acl:agentClass acl:AuthenticatedAgent;
	    acl:accessToClass acl:Resource; # NB this is the default

	    # apps the user has tagged "Chat.Public" or "Chat.*" or "*.Public" or
	    # "*" for acl:Read will be allowed.
	    acl:tag "Chat.Public";

	    acl:default true .

If any of the tag patterns that the user has assigned to the app that she's
using matches any of the tag patterns in the `acl:Authorization`, then it's
as if there was an `acl:app` match. Note that there is no global vocabulary
of tags/scopes; tags are arbitrary, and what tags to assign to authorizations
is entirely at the discretion of a resource owner. Tags **SHOULD** have the
same meaning at least across resources in the same origin and [realm][].

The user associates tag patterns for the combination of an app, resource
server origin, and optionally security realm (the name of the [protection space][realm];
that is, the `realm` authentication parameter of the `WWW-Authenticate` HTTP
response header) in an App Authorization document. Here is an example App
Authorization document assigning tag patterns `Photos.Public` and `Chat.*` to
app `https://app.example/oauth/code` when accessing server `https://mike.example`'s
realm `https://mike.example/auth/` for modes `acl:Read` and `acl:Write`:

	# this is world-readable but has an unguessable URI like
	#     <https://mike.example/wac/app-auth/b6d88441302c07700743b8d793ae2a8a.ttl#it>
	# in a non-listable container.
	
	@prefix acl: <http://www.w3.org/ns/auth/acl#> .
	
	<#it>
	    a acl:AppAuthorization;
	    acl:resourceServer [
	        acl:origin <https://mike.example>;
	        acl:realm "https://mike.example/auth/"
	    ];
	    acl:app "https://app.example/oauth/code";
	    acl:tagMode [
	        acl:tag "Photos.Public", "Chat.*";
	        acl:mode acl:Read, acl:Write
	    ] .

If the `acl:resourceServer` specifies an `acl:realm` then it **MUST** match
the server's realm exactly.  Note that `auth.py` uses its base URL as its
realm.

To support a default App Authorization, the `acl:resourceServer` can give the
literal `"*"` for `acl:origin`, which matches all servers. However, a server
**MUST** ignore any `acl:tag`s containing a wildcard character (`*` or `?`)
if the server's origin is not in the `acl:resourceServer`.

The URI for the App Authorization document **MUST** be in (at a sub-path of)
an `acl:appAuthorizations` in the user's profile:

	<#me> acl:appAuthorizations </wac/app-auth/> .

This container/directory **SHOULD** be configured to allow read of App
Authorization documents by anyone and any origin; however, to protect the
user's privacy (specifically, what apps the user uses and what resource servers
the user accesses with those apps) including from other apps the user uses,
listing the container's contents should be restricted to only the user, and
then to only the user's trusted authorization management app.

The method by which an app discovers its App Authorization URIs is to be
determined. It is envisioned that each app will have an App Authorizations
index file, generated and maintained by the user's trusted authorization
management app, stored in a non-listable container, with a URI derived from
the app's identifier, and readable only by the user and only when using that
app, mapping between App Authorization URIs and resource servers:

	# App Authorizations index file for app "https://app.example/oauth/code".
	@prefix acl: <http://www.w3.org/ns/auth/acl#> .

	</wac/app-auth/b6d88441302c07700743b8d793ae2a8a.ttl#it>
	    acl:resourceServer [ acl:origin <https://mike.example>; acl:realm "https://mike.example/auth/" ] .

	</wac/app-auth/4f20846c1179e604048a589583dd6f9c.ttl#it>
	    acl:resourceServer [ acl:origin <https://other.example>; acl:realm "Other Server" ] .

The non-listable container for App Authorization index files **SHOULD** return
identical HTTP `403` responses both for accesses to non-existent index files
and for accesses to existing index files which are not for the user∙app
requesting it, so that an adversary (other user or other app) can't probe for
index files to discover what apps the user might use.

The method by which the tag vocabulary being used by a server is communicated
to the user or to the user's trusted authorization management app is to be
determined.

To associate tags with a `Bearer` access token, the app sets the new
`app_authorizations` claim in the *proof-token* (sent to the `webid-pop`
endpoint) to the URI(s) of the App Authorization(s) appropriate for this
server. The claim can either be a string (for one URI) or a list of strings
(for multiple URIs). The server will load at most four App Authorization URIs.

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
  - `webid-pop` -- The `token_pop_endpoint` of
    [WebID HTTP Authorization Protocol][zenomt-auth]; see that document
    for a description of this endpoint's API

In addition, the server provides the following default HTML pages (located
in the `www` directory) for logging in, refreshing, and forbidding access:

  - `401.html` -- The normal *Unauthorized* error page that prompts the user
    to log in;
  - `401refresh.html` -- An error  page that causes the user's web browser
     to refresh the user's credentials;
  - `403.html` -- An error page for when access to the resource is completely
    forbidden;
  - `403logout.html` -- An error page for when access is forbidden, but where
    an alternate login might provide access.

### `authcheck` API

The `authcheck` endpoint is accessed with the `GET` method, and with some
custom headers listed below. *nginx* ordinarily forwards the entire original
request as-is (including method, but to the subrequest URI), so a little
re-writing is needed. See the configuration below.

#### Request Headers

  - `X-Original-URI` - The absolute request URI of the request being checked,
    including scheme, host, port, and path. See the configuration below for
    how to construct this from existing *nginx* variables;
  - `X-Original-Method` - The method from the original request, needed because
    this endpoint is accessed with `GET`;
  - `X-Forwarded-For` - The IP address of the client making the request.
  - All other headers from the original request, except that `Content-Length`
    should be `0` or suppressed. `authcheck` will look at the `Cookie`,
    `Origin`, and `Authorization` headers.

#### Response Status

  - `200` - Access permitted;
  - `401` - Authorization required;
  - `403` - Access forbidden;
  - `500` - Any internal error, including misconfiguration or malformed
    ACL files.

#### Response Headers

  - `User` - If set, the authenticated WebID of the requester. Intended to
    allow the WebID to be logged in *nginx* log files if desired;
  - `X-Auth-Mode` - If set, extra information for `401` or `403` responses;
    Possible values are `refresh`, `token`, and `logout`. In the sample
    configuration, this value is used to modify which `401` or `403` HTML
    page is presented, to allow the user to log in, refresh a stale session,
    log out and try a different identity, or be informed of an invalid access
    token;
  - `X-Auth-Info` - If set, extra information for `200` responses with
    additional information about the client. Its value is a Base64-URL encoded
    JSON object with the following keys:
    - `webid` - The authenticated WebID (same as the `User` header);
    - `appid` - The application identifier, which might be the `Origin`
      header or an identifier associated with a `Bearer` access token;
    - `mode` - The Web Access Control permission mode (full URI)
      that was matched to grant access. This is to allow a downstream application
      to constrain the behavior of a write-like method if only
      `http://www.w3.org/ns/auth/acl#Append` permission is granted.
  - `WWW-Authenticate` - If set, the `WWW-Authenticate` header that should
    be returned to the client with a `401` response. *nginx* automatically
    includes this response header with a `401` response to the client, so it
    doesn't need to be manually configured. This header includes parameters
    for [WebID HTTP Authorization Protocol][zenomt-auth] including a challenge
    `nonce` and the `token_pop_endpoint` URI.

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
endpoint requires a different configuration than the others, in order to
change the request method to `GET`, suppress the request body (if any), and
set required API request headers:

	server {
	    server_name mike.example;
	    ...

	    location /auth/authcheck {
	        internal; # don't expose to the outside
	        auth_request off; # don't get stuck in a loop
	        proxy_method GET;
	        proxy_pass_request_body off;
	        proxy_set_header Content-length ""; # since there's no request body
	        proxy_pass http://127.0.0.1:8080;
	        proxy_set_header X-Original-URI $scheme://$host:$server_port$request_uri;
	        proxy_set_header X-Original-Method $request_method;
	        proxy_set_header X-Forwarded-For $remote_addr;
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

If you don't already have a [Cross-Origin Resource Sharing (CORS)][CORS]
configuration and you want to add cross-origin support, you can create a
`cors.conf` file to make it easier to add later on in different *nginx*
configuration locations.  For example (remember that any `add_header` directive
in an *nginx* `location` or sub-`location` block clears all inherited
`add_headers`):

	add_header Access-Control-Allow-Origin "$http_origin" always;
	add_header Access-Control-Expose-Headers "Age,Content-Range,ETag,Link,Location,User,Vary,WWW-Authenticate" always;

	if ($request_method = 'OPTIONS') {
	    add_header Access-Control-Allow-Origin "$http_origin";
	    add_header Access-Control-Allow-Headers "Cache-Control,If-Match,If-None-Match,If-Modified-Since,If-Unmodified-Since,If-Range,Range,Authorization,Content-Type,Link,Slug";
	    add_header Access-Control-Allow-Methods "OPTIONS,HEAD,GET,PATCH,POST,PUT,DELETE,PROPFIND,PROPPATCH,MKCOL,COPY,MOVE,LOCK,UNLOCK";
	    add_header Access-Control-Max-Age 60;
	    return 204;
	}

Configure location(s) to use `auth.py` for authorization and access control, and to
use `auth.py`'s HTML pages for `401` and `403` responses:

	    ...
	    location /wac {
	        auth_request /auth/authcheck;
	        auth_request_set $auth_mode $upstream_http_x_auth_mode; # extract x-auth-mode for 401/403 pages
	        error_page 401 /auth/401$auth_mode.html; # select plain, refresh, or token flavor
	        error_page 403 /auth/403$auth_mode.html; # select plain or logout flavor
	
	        # if you want to support CORS and created a file as above:
	        include cors.conf;
	
	        # alternatively you could include CORS directives inline here.

	        # Solid says to set the User response header to the authenticated webid:
	        auth_request_set $auth_webid $upstream_http_user;
	        add_header User $auth_webid; # caution: this would reset all inherited add_headers
	    }
	    ...

client.py
---------
This is a test client for the [WebID Authorization Protocol][zenomt-auth].
It challenges a URI for a `WWW-Authenticate` header, and if the server appears
to use the authorization protocol, the test client tries to obtain an access
token that you can then use with a tool like `curl` (until the token expires).

`client.py` can either generate a [self-issued][] `id_token` (default) or,
if you have access to the private key of your OIDC issuer, it can pretend to
be your normal issuer by using the `-i` option.

For the self-issued case, you must add the self-issuer URI and a public key
to your WebID profile.

First, if you don't already have one, generate an RSA private/public key pair
and find the exponent (`e`) and modulus:

	$ openssl genrsa -out data/client-private.pem 2048
	Generating RSA private key, 2048 bit long modulus
	......+++
	.........................................................................................+++
	e is 65537 (0x010001)
	
	$ openssl rsa -in data/client-private.pem -outform PEM -pubout -out data/client-public.pem
	writing RSA key
	
	$ openssl rsa -pubin -in data/client-public.pem -noout -modulus
	Modulus=D7B6DF2DF09F251546CAE49F76A0DE93DDE126EA10EF65A1E3B08748FED6847E5B1CD6E4210707A064831C3C9F57297D8F5F65DDE4FEEF9FF36D579533AB75984E4C8E4AD9493CF611A91DC9BEC5311CB3AF293BFDCD5D701F58C91A708F6FAD6CF15A413264ECDBC0983EE99AB3628D5DC4731AE0E5F7B8F814CD297A4FDD63854221CB6EF67B336790F1873D42F7E2027FADFFEE8884A35809893F0534683C40321DD62EFBC706F68516A6C0F1A331059EFF7ACE109D795260EBC8223809F36A25BFF048E60E0C81ECA686852D117B4AC51BE3991F3C1A1D563E118B8630055A39B4CC5AA265B1555E2A67A8A2C96D3E0674164EDA97806893C694D012A5EC

Add your RSA public key and self-issuer URI to your WebID profile:

	@prefix cert:  <http://www.w3.org/ns/auth/cert#> .
	@prefix solid: <http://www.w3.org/ns/solid/terms#> .
	@prefix xsd:   <http://www.w3.org/2001/XMLSchema#> .
	
	<#me>
	    solid:oidcIssuer <https://self-issued.me>;
	
	    cert:key [
	        a cert:RSAPublicKey;
	        cert:exponent 65537;
	        cert:modulus "D7B6DF...A5EC"^^xsd:hexBinary # full modulus elided for clarity
	    ].

Now you're ready to get an access token. Using the example configuration from
above and the [samples](samples) directory:

	$ python client.py -k data/client-private.pem -w 'https://mike.example/card.ttl#me' https://mike.example/wac/check.html -A https://mike.example/wac/app-auth/b6d88441302c07700743b8d793ae2a8a.ttl#it
	{
	    "access_token": "a0wBCgJajBtKX2PZ1-Uy6ATW2unYMeFxqyAXoV12",
	    "token_type": "Bearer",
	    "expires_in": 180
	}

You can now use the `access_token` with `curl` to access that resource and
any others for which this auth server is configured, for the next 180 seconds:

	$ curl https://mike.example/wac/check.html -H 'Authorization: Bearer a0wBCgJajBtKX2PZ1-Uy6ATW2unYMeFxqyAXoV12'
	...



  [auth-module]: https://nginx.org/en/docs/http/ngx_http_auth_request_module.html
  [CORS]:        https://www.w3.org/TR/cors/
  [nginx]:       https://nginx.org/
  [solid]:       https://github.com/solid/solid
  [WAC]:         https://github.com/solid/web-access-control-spec
  [WebID-OIDC]:  https://github.com/solid/webid-oidc-spec
  [zenomt-auth]: https://github.com/zenomt/webid-auth-protocol
  [self-issued]: https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued
  [realm]:       https://tools.ietf.org/html/rfc7235#section-2.2
  [priv-proto]:  https://github.com/solid/authorization-and-access-control-panel/blob/master/privilege-request-protocol.md
  [tags]:        https://github.com/solid/authorization-and-access-control-panel/blob/master/Proposals/ReplaceTrustedAppsWithTags.md
