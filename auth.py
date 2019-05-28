#! /usr/bin/env python --

#   Copyright 2019 Michael Thornburgh
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import argparse
import base64
import binascii
import hashlib
import io
import json
import mimetypes
import os
import posixpath
import rdflib
import re
import sqlite3
import sys
import thread
import time
import traceback
import urllib
import urllib2
import urlparse

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred, succeed
from twisted.python import log
from twisted.web import resource, server
from twisted.web.client import readBody, Agent, ContentDecoderAgent, FileBodyProducer, GzipDecoder, RedirectAgent
from twisted.web.http import proxiedLogFormatter
from twisted.web.http_headers import Headers


RANDOM_TOKEN_LENGTH = 30

ACL_MODE           = rdflib.URIRef('http://www.w3.org/ns/auth/acl#mode')
ACL_APP            = rdflib.URIRef('http://www.w3.org/ns/auth/acl#app')
ACL_ORIGIN         = rdflib.URIRef('http://www.w3.org/ns/auth/acl#origin')
ACL_DEFAULT        = rdflib.URIRef('http://www.w3.org/ns/auth/acl#default')
ACL_AGENT          = rdflib.URIRef('http://www.w3.org/ns/auth/acl#agent')
ACL_AGENTCLASS     = rdflib.URIRef('http://www.w3.org/ns/auth/acl#agentClass')
ACL_AGENTGROUP     = rdflib.URIRef('http://www.w3.org/ns/auth/acl#agentGroup')
ACL_AUTHORIZATION  = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Authorization')
ACL_READ           = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Read')
ACL_WRITE          = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Write')
ACL_APPEND         = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Append')
ACL_CONTROL        = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Control')
ACL_OTHER          = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Other')
FOAF_AGENT         = rdflib.URIRef('http://xmlns.com/foaf/0.1/Agent')
SOLID_OIDCISSUER   = rdflib.URIRef('http://www.w3.org/ns/solid/terms#oidcIssuer')
VCARD_HASMEMBER    = rdflib.URIRef('http://www.w3.org/2006/vcard/ns#hasMember')

DEFAULT_NS = {
	"foaf": rdflib.URIRef('http://xmlns.com/foaf/0.1/'),
	"acl": rdflib.URIRef('http://www.w3.org/ns/auth/acl#'),
	"solid": rdflib.URIRef('http://www.w3.org/ns/solid/terms#'),
	"vcard": rdflib.URIRef('http://www.w3.org/2006/vcard/ns#')
}

DEFAULT_NS_TTL = """
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
@prefix vcard: <http://www.w3.org/2006/vcard/ns#> .
"""

METHODS_READ   = ["OPTIONS", "GET", "HEAD", "TRACE", "PROPFIND"]
METHODS_WRITE  = ["PUT", "POST", "DELETE", "PATCH", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]
METHODS_APPEND = ["PUT", "POST", "PATCH", "PROPPATCH", "MKCOL"]

inf = float('inf')

def b64u_encode(s):
	return base64.urlsafe_b64encode(s).rstrip('=')

def b64_padding(s):
	padding = '=' * (4 - (len(s) % 4))
   	return '' if len(padding) == 4 else padding

def b64u_decode(s):
	s = str(s)
	return base64.urlsafe_b64decode(s + b64_padding(s))

def qparam(params, key):
	return params.get(key, [None])[0]

def urlencode(query):
	# urllib.urlencode will encode a None value as a string None.
	# this will suppress None and empty values.
	rv = []
	for k, v in query.iteritems():
		if v:
			rv.append('%s=%s' % (urllib.quote_plus(str(k)), urllib.quote(str(v), '')))
	return '&'.join(rv)

def compact_json(obj):
	return json.dumps(obj, indent=None, separators=(',', ':'))

def b64u_sha512(msg):
	return b64u_encode(hashlib.sha512(msg).digest())

def b64u_sha256(msg):
	return b64u_encode(hashlib.sha256(msg).digest())

def random_token():
	return b64u_encode(os.urandom(RANDOM_TOKEN_LENGTH))

def asyncResponse(f):
	def wrapper(*s, **kw):
		f(*s, **kw)
		return server.NOT_DONE_YET
	return wrapper

def delay(interval):
	d = Deferred()
	reactor.callLater(interval, d.callback, None)
	return d

def bytesProducer(b):
	return FileBodyProducer(io.BytesIO(b))

def canonical_origin_parsed(urlparts):
	scheme = urlparts.scheme.lower()
	port = urlparts.port or { 'http':80, 'https':443 }.get(scheme, None)
	return ('%s://%s:%s' % (scheme, urlparts.hostname or '', port)).lower()

def canonical_origin(uri):
	return canonical_origin_parsed(urlparse.urlparse(uri))

def load_local_graph(path, publicID):
	try:
		if args.debug:
			print "loading", path
		rv = rdflib.Graph()
		rv.parse(data=DEFAULT_NS_TTL + open(path, 'rb').read(), format='turtle', publicID=publicID)
		return rv
	except Exception as e:
		print "error loading ACL <%s> (%s)" % (publicID, path)
		raise e


parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', type=int, default=8080, help='listen on port (default %(default)s)')
parser.add_argument('-a', '--address', default="127.0.0.1",
	help='listen on address (default %(default)s)')
parser.add_argument('-d', '--database', default='./data/storage.sqlite',
	help='database file (default %(default)s)')
parser.add_argument('-c', '--config-file', default='./data/config.json',
	help='configuration file (default %(default)s)')
parser.add_argument('--docroot', default='./www',
	help='base directory for simple file server (default %(default)s)')
parser.add_argument('-l', '--session-lifetime', help="lifetime for sessions (default %(default)s)", default=86400)
parser.add_argument('-t', '--token-lifetime', help="lifetime for access tokens (default %(default)s)", default=1800)
parser.add_argument('-i', '--cleanup-interval', type=float, default=10.,
	help="interval between database cleanup runs (default %(default).3f)")
parser.add_argument('-r', '--max-refreshes', default=1, type=int,
	help="maximum failed refreshes before requiring a login (default %(default)s)")
parser.add_argument('--acl-suffix', default='.acl',
	help="filename suffix for access control files (default %(default)s)")
parser.add_argument('--debug', action='store_true')
parser.add_argument('url', help='my auth URL prefix')

args = parser.parse_args()

ISSUER_LIFETIME = args.session_lifetime * 2
MAX_ISSUER_LIFETIME = 86400 * 180

urlPathPrefix = urlparse.urlparse(args.url).path
if urlPathPrefix[-1] != '/':
    raise ValueError("url must end in a slash")

log.startLogging(sys.stdout)

db = sqlite3.connect(args.database)
db.row_factory = sqlite3.Row

# locations = [ { origin, prefix, root, base }, ... ]
locations = []
config_file = json.loads(open(args.config_file, 'rb').read())

agent = ContentDecoderAgent(RedirectAgent(Agent(reactor)), [(b"gzip", GzipDecoder)])


def prepare_locations():
	for prefix, root in config_file['locations'].items():
		urlparts = urlparse.urlparse(prefix)
		origin = canonical_origin_parsed(urlparts)
		prefix = urlparts.path
		prefix = prefix if prefix[-1] == '/' else prefix + '/'
		root = root if root[-1] == '/' else root + '/'
		locations.append(dict(origin=origin, prefix=prefix, root=root, base=origin + prefix))
	locations.sort(reverse=True, key=lambda x: x['prefix'].count('/'))

def find_location(uri):
	urlparts = urlparse.urlparse(uri)
	origin = canonical_origin_parsed(urlparts)
	path = posixpath.normpath(urlparts.path)
	for each in locations:
		prefix = each['prefix']
		if each['origin'] == origin:
			if (prefix == path[:len(prefix)]) or (prefix[:-1] == path):
				rv = dict(path=path[len(prefix):])
				rv.update(each)
				return rv

@inlineCallbacks
def do_cleanup():
	while True:
		now = time.time()
		try:
			db.rollback()
			c = db.cursor()
			c.execute("DELETE FROM issuer WHERE expires_on < ?", (now, ))
			c.execute("DELETE FROM session WHERE expires_on < ?", (now, ))
			c.execute("DELETE FROM auth_state WHERE expires_on < ?", (now, ))
			c.execute("DELETE FROM access_token WHERE expires_on < ?", (now, ))
			c.execute("DELETE FROM token_challenge WHERE expires_on < ?", (now, ))
			db.commit()
		except sqlite3.OperationalError:
			db.rollback()
			print traceback.format_exc()
			print "will retry in", args.cleanup_interval
		yield delay(args.cleanup_interval)

class AuthResource(resource.Resource):
	COOKIE = 'webid_auth_session_' + binascii.hexlify(hashlib.sha512(args.url).digest()[:8])

	AUTHCHECK = "authcheck"
	LOGIN     = "login"
	REFRESH   = "refresh"
	CODE      = "code"
	LOGOUT    = "logout"
	WEBID_POP = "webid-pop"

	MODE_REFRESH = "refresh"
	MODE_LOGOUT  = "logout"
	MODE_TOKEN   = "token"

	STATUS_OK        = "ok"
	STATUS_STALE     = "stale"
	STATUS_BAD_TOKEN = "bad token"
	STATUS_NONE      = None

	PERM_OK     = "ok"
	PERM_AUTH   = "authenticate"
	PERM_NOTYOU = "not you"
	PERM_NONE   = None

	isLeaf = True

	def log_message(self, fmt, *s):
		log.msg(fmt % s)

	def get_auth_header(self, request, header_type):
		header = request.getHeader('Authorization')
		if header:
			fields = re.split(r'\s+', header, 1)
			if len(fields) == 2:
				authtype, val = fields
				if authtype.lower() == header_type.lower():
					return val

	def get_client_addr(self, request):
		return request.getHeader('X-Forwarded-For') or request.getClientIP()

	def get_bearer_auth(self, request):
		return self.get_auth_header(request, 'Bearer')

	def get_safe_redirect(self, url):
		url = urlparse.urljoin(args.url, url)
		myparts = urlparse.urlparse(args.url)
		parts = urlparse.urlparse(url)
		if url.startswith(args.url) or ('https' != parts.scheme) or (myparts.hostname != parts.hostname):
			return None
		return url

	def normalize_issuer(self, url):
		parts = urlparse.urlparse(url)
		path = '.' if parts.path.endswith('/') else parts.path + '/'
		return urlparse.urljoin(url, path)

	def send_answer(self, request, body='', code=200, content_type='text/plain', other_headers=[], cache=False, location=None):
		request.setResponseCode(code)
		request.setHeader('Content-type', content_type)
		request.setHeader('Content-length', len(body))
		request.setHeader('Cache-control', 'max-age=300' if cache else 'no-cache, no-store')
		if location:
			request.setHeader('Location', location)
		for h, v in other_headers:
			request.setHeader(h, v)
		request.write(body)
		request.finish()
		db.commit()
		return server.NOT_DONE_YET

	def answer_file(self, request, path, cache=False):
		path = posixpath.normpath(path)
		words = path.split('/')
		path = args.docroot
		for word in words:
			if os.path.dirname(word) or word in (os.curdir, os.pardir):
				continue
			path = os.path.join(path, word)
		if os.path.isdir(path):
			return self.send_answer(request, 'not found', code=404)
		content_type = mimetypes.guess_type(path)[0] or 'application/octet-stream'
		other_headers = [('Access-Control-Expose-Headers', 'WWW-Authenticate'),
				('Access-Control-Allow-Origin', request.getHeader('Origin') or '*')]
		try:
			with open(path, 'rb') as f:
				return self.send_answer(request, f.read().replace('%%AUTH_URL%%', args.url), content_type=content_type, cache=cache, other_headers=other_headers)
		except Exception as e:
			# print traceback.format_exc()
			pass
		return self.send_answer(request, 'not found', code=404)

	def _auth_app_filter(self, sub, appid, app_origin, inherited, graph):
		if inherited and ((sub, ACL_DEFAULT, None) not in graph):
			return False
		if appid: # None means no check needed
			for obj in graph.objects(sub, ACL_ORIGIN):
				obj = unicode(obj)
				if ("*" == obj) or (canonical_origin(obj) == app_origin):
					return True
			for obj in graph.objects(sub, ACL_APP):
				if appid.startswith(unicode(obj)):
					return True
			return False
		return True

	@inlineCallbacks
	def check_acl_for_perm(self, acl, webid, appid, app_origin, permission, inherited=False):
		initBindings = dict(perm=permission, webid=webid)
		auth_app_filter = lambda x: self._auth_app_filter(x[0], appid, app_origin, inherited, acl)
		filtered_query = lambda q: filter(auth_app_filter, acl.query(q, initNs=DEFAULT_NS, initBindings=initBindings))

		if filtered_query("SELECT DISTINCT ?auth WHERE { ?auth a acl:Authorization; acl:agentClass foaf:Agent; acl:mode ?perm }"):
			returnValue(self.PERM_OK)

		if not webid:
			if filtered_query("SELECT DISTINCT ?auth WHERE { ?auth a acl:Authorization; acl:mode ?perm }"):
				returnValue(self.PERM_AUTH)
			returnValue(self.PERM_NONE)

		if filtered_query("SELECT DISTINCT ?auth WHERE { ?auth a acl:Authorization; acl:agentClass acl:AuthenticatedAgent; acl:mode ?perm }"):
			returnValue(self.PERM_OK)

		if filtered_query("SELECT DISTINCT ?auth WHERE { ?auth a acl:Authorization; acl:agent ?webid; acl:mode ?perm }"):
			returnValue(self.PERM_OK)

		for (auth, ) in filtered_query("SELECT DISTINCT ?auth WHERE { ?auth a acl:Authorization; acl:agentGroup ?g; acl:mode ?perm }"):
			for group in acl.objects(auth, ACL_AGENTGROUP):
				yield None # XXX make this function async, remove when it really is
				print "XXX should check out group someday", unicode(group)
				# try:
				#	group_graph = load_graph_cached_shared_timeout(group)
				#	if (group, VCARD_HASMEMBER, webid) in group_graph:
				#		returnValue(self.PERM_OK)
				# except Exception as e:
				#	print "error loading group <%s>: %s" % (unicode(group), `e`)

		if filtered_query("SELECT DISTINCT ?auth WHERE { ?auth a acl:Authorization; acl:mode ?perm }"):
			returnValue(self.PERM_NOTYOU)

		returnValue(self.PERM_NONE)

	@inlineCallbacks
	def check_permission(self, method, uri, webid, appid):
		location = find_location(uri) # { origin, prefix, root, base, path }
		if not location:
			raise ValueError("missing configuration for <%s>" % (uri, ))
		path = location['path'].split('/')
		if posixpath.isdir(location['root'] + location['path']):
			leaf = None
		else:
			leaf = path[-1]
			path = path[:-1] or ['']
		if path[0]:
			path.insert(0, '')
		lastACL = None
		aclURI = location['base']
		cachedReadable = False
		current_dir = location['root']
		app_origin = canonical_origin(appid) if appid else None

		for dir_ in path:
			current_dir = posixpath.join(current_dir, dir_ )
			aclFilename = posixpath.join(current_dir, args.acl_suffix)
			aclURI = urlparse.urljoin(aclURI, (dir_ or '.') + '/' + args.acl_suffix)
			if posixpath.isfile(aclFilename):
				cachedReadable = False
				lastACL = load_local_graph(aclFilename, aclURI)
				reason = yield self.check_acl_for_perm(lastACL, webid, appid, app_origin, ACL_READ)
				if reason is not self.PERM_OK:
					returnValue((reason, None))
			elif not lastACL:
				raise ValueError("missing root ACL (%s) <%s>?" % (aclFilename, aclURI))
			elif not cachedReadable:
				reason = yield self.check_acl_for_perm(lastACL, webid, appid, app_origin, ACL_READ, inherited=True)
				if reason is not self.PERM_OK:
					returnValue((reason, None))
				cachedReadable = True

		using_inherited = cachedReadable
		need_control = False

		if leaf:
			if leaf.endswith(args.acl_suffix):
				need_control = True
			else:
				leaf += args.acl_suffix
			aclFilename = posixpath.join(current_dir, leaf)
			aclURI = urlparse.urljoin(aclURI, leaf)
			if posixpath.isfile(aclFilename):
				lastACL = load_local_graph(aclFilename, aclURI)
				using_inherited = False
			else:
				using_inherited = True

		check_for = lambda perm: self.check_acl_for_perm(lastACL, webid, appid, app_origin, perm, inherited=using_inherited)

		if   need_control:
			mode = ACL_CONTROL
			reason = yield check_for(ACL_CONTROL)
		elif method in METHODS_READ:
			mode = ACL_READ
			reason = yield check_for(ACL_READ)
		elif method in METHODS_WRITE:
			mode = ACL_WRITE
			reason = yield check_for(ACL_WRITE)
			if (reason is not self.PERM_OK) and (method in METHODS_APPEND):
				mode = ACL_APPEND
				reason = yield check_for(ACL_APPEND)
		else:
			mode = ACL_OTHER
			reason = yield check_for(ACL_OTHER)

		returnValue((reason, unicode(mode)))

	def check_auth_status(self, request):
		access_token = self.get_bearer_auth(request)
		if access_token:
			request.access_token_row = db.cursor().execute("SELECT * FROM access_token WHERE access_token = ?", (access_token, )).fetchone()
			if request.access_token_row:
				request.session_webid = request.access_token_row['webid']
				return self.STATUS_OK
			return self.STATUS_BAD_TOKEN

		if not request.session_row:
			return self.STATUS_NONE

		now = long(time.time())
		if request.session_row['id_expires_on'] < now:
			if request.session_row['refresh_count'] >= args.max_refreshes:
				return self.STATUS_NONE

			return self.STATUS_STALE

		return self.STATUS_OK

	def make_token_challenge(self, uri, request):
		nonce = random_token()
		db.cursor().execute("INSERT INTO token_challenge (nonce, uri, host) VALUES (?, ?, ?)",
			(nonce, uri, self.get_client_addr(request)))
		return nonce

	@inlineCallbacks
	def answer_authcheck(self, request):
		uri = request.getHeader('X-Original-URI')
		if not uri:
			raise ValueError("X-Original-URI header missing")
		print "authcheck <%s>" % (uri, )
		status = self.check_auth_status(request)
		method = request.getHeader('X-Original-Method')
		if not method:
			raise ValueError("X-Original-Method header missing")
		appid = request.access_token_row['appid'] if request.access_token_row else request.getHeader('Origin')
		webid = rdflib.URIRef(request.session_webid) if status == self.STATUS_OK else None

		def send_auth_answer(code, authMode=None, info=None):
			other_headers = []
			www_authenticate = ['Bearer realm="%s", scope="openid webid"' % (args.url, )]
			if webid:
				other_headers.append(('User', webid))
			if info:
				other_headers.append(('X-Auth-Info', info))
			if authMode:
				other_headers.append(('X-Auth-Mode', authMode))
				if not request.auth_cookie:
					www_authenticate.append('error="invalid_token"')
			if 401 == code:
				www_authenticate.append('webid_pop_endpoint="%s"' % (args.url + self.WEBID_POP, ))
				www_authenticate.append('nonce="%s"' % (self.make_token_challenge(uri, request), ))
				other_headers.append(('WWW-Authenticate', ", ".join(www_authenticate)))
			return self.send_answer(request, code=code, other_headers=other_headers)

		if status == self.STATUS_BAD_TOKEN:
			returnValue(send_auth_answer(401, authMode=self.MODE_TOKEN))

		perm, mode = yield self.check_permission(method, uri, webid, appid)

		if perm == self.PERM_OK:
			info = dict(webid=webid, appid=appid, mode=mode)
			returnValue(send_auth_answer(200, info=b64u_encode(compact_json(info))))
		elif perm == self.PERM_AUTH:
			returnValue(send_auth_answer(401, authMode=self.MODE_REFRESH if status == self.STATUS_STALE else None))
		else:
			returnValue(send_auth_answer(403, authMode=self.MODE_LOGOUT if perm == self.PERM_NOTYOU else None))

	@inlineCallbacks
	def get_url(self, url, obj=None, query=None, basic_auth=None, bearer_auth=None):
		try:
			headers = Headers()
			requestBody = None
			if obj:
				requestBody = json.dumps(obj)
				headers.addRawHeader('Content-type', 'application/json')
			elif query:
				requestBody = urlencode(query)
				headers.addRawHeader('Content-type', 'application/x-www-form-urlencoded')
			if basic_auth:
				l, p = basic_auth
				headers.addRawHeader('Authorization', 'Basic ' + base64.b64encode(l + ':' + p))
			elif bearer_auth:
				headers.addRawHeader('Authorization', 'Bearer ' + bearer_auth)
			d = agent.request(b"POST" if requestBody else b"GET", bytes(url), headers,
					bytesProducer(requestBody) if requestBody else None)
			response = yield d
			body = yield readBody(response)
			returnValue((response, body))
		except Exception as e:
			print traceback.format_exc()
			returnValue((None, None))

	@inlineCallbacks
	def create_issuer(self, issuer_url):
		def suburl(url):
			return urlparse.urljoin(issuer_url, url) if url else None

		try:
			db.rollback()
			response, body = yield self.get_url(suburl('.well-known/openid-configuration'))
			if 200 != response.code:
				returnValue(None)
			config = json.loads(body)
			if (not config.get('authorization_endpoint')) or (not config.get('token_endpoint')) \
					or (not config.get('jwks_uri')) or (not config.get('registration_endpoint')):
				returnValue(None)
			registrationResponse, registrationBody = yield self.get_url(suburl(config['registration_endpoint']), \
					obj={ "response_types": [ "code" ], "redirect_uris": [ args.url + self.CODE ] })
			if registrationResponse.code not in [200, 201]:
				print "didn't register right"
				returnValue(None)
			registration = json.loads(registrationBody)
			if not registration.get('client_id'):
				print "no client id"
				returnValue(None)

			now = long(time.time())
			auth_modes = config.get('token_endpoint_auth_methods_supported', ["client_secret_basic"])
			hard_expiration = min(registration.get('client_secret_expires_at', 0) or now + MAX_ISSUER_LIFETIME, now + MAX_ISSUER_LIFETIME)
			lifetime = max(60, min(ISSUER_LIFETIME, hard_expiration - now))
			c = db.cursor()
			c.execute("INSERT INTO issuer "
					"(expires_on, hard_exp_on, lifetime, issuer_url, client_id, client_secret, userinfo_url, "
					"    auth_url, token_url, jwks_url, secret_post, secret_basic) "
					"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
						now + lifetime, hard_expiration, lifetime,
						issuer_url,
						registration.get('client_id'), registration.get('client_secret'),
						suburl(config.get('userinfo_endpoint')),
						suburl(config.get('authorization_endpoint')),
						suburl(config.get('token_endpoint')),
						suburl(config.get('jwks_uri')),
						"client_secret_post" in auth_modes, "client_secret_basic" in auth_modes
					))
			rv = c.execute("SELECT * FROM issuer WHERE id = ?", (c.lastrowid, )).fetchone()
			db.commit()
			returnValue(rv)
		except Exception as e:
			print traceback.format_exc()
			db.rollback()
			returnValue(None)

	def nonce_from_state(self, state):
		return b64u_sha256(state)[:16]

	@inlineCallbacks
	def load_graph(self, url):
		response, body = yield self.get_url(url)
		if 200 != response.code:
			raise ValueError("unexpected response code %d" % (response.code, ))
		rv = rdflib.Graph()
		content_type = response.headers.getRawHeaders("content-type", [None])[0]
		content_type = re.split(r' *; *', content_type)[0] if content_type else None
		rv.parse(data=body, format=content_type, publicID=url)
		returnValue(rv)

	@inlineCallbacks
	def check_id_token(self, raw_token, state, issuer_row):
		enc_header, enc_claims, enc_sig = raw_token.split('.')
		claims = json.loads(b64u_decode(enc_claims))
		webid = claims.get('webid') or claims.get('sub') or ''
		issuer_url = issuer_row['issuer_url']
		nonce = claims.get('nonce') or ''
		webid_parts = urlparse.urlparse(webid)
		issuer_parts = urlparse.urlparse(issuer_url)
		my_client = issuer_row['client_id']

		if not webid:
			raise ValueError("id_token doesn't identify a webid")

		if self.normalize_issuer(claims.get("iss")) != self.normalize_issuer(issuer_url):
			raise ValueError("id_token doesn't claim issuer")

		aud = claims["aud"]
		if (aud != my_client) and not isinstance(aud, list):
			raise ValueError("i am not the audience")
		if isinstance(aud, list) and my_client not in aud:
			raise ValueError("audience list doesn't include me")

		if claims.get("azp") and (claims.get("azp") != my_client):
			raise ValueError("authorized party mismatch")

		if claims.get("exp", 0) < time.time():
			raise ValueError("id_token expires in the past")

		if nonce != self.nonce_from_state(state):
			raise ValueError("invalid nonce")
		if ('https' != webid_parts.scheme):
			raise ValueError("webid scheme is not https")

		card = yield self.load_graph(webid)
		webid_ref = rdflib.URIRef(webid)
		issuer_ref = rdflib.URIRef(issuer_url)

		if (webid_ref, SOLID_OIDCISSUER, None) in card:
			if (webid_ref, SOLID_OIDCISSUER, issuer_ref) not in card:
				raise ValueError("webid <%s> lists issuers but not <%s>" % (webid, issuer_url))
		elif not webid_parts.hostname.endswith(issuer_parts.hostname):
			raise ValueError("webid <%s> hostname is not a subdomain of issuer <%s> hostname" % (webid, issuer_url))

		returnValue((claims, webid))

	def basic_answer_login(self, request, issuer, orig_url):
		if not issuer:
			return self.send_answer(request, 'problem with issuer', code=302, location=orig_url)

		state_key = random_token()
		nonce = self.nonce_from_state(state_key)
		query = dict(state=state_key, nonce=nonce, client_id=issuer['client_id'], response_type="code",
			scope="openid webid", redirect_uri=args.url + self.CODE)
		location = issuer['auth_url'] + '?' + urlencode(query)

		db.cursor().execute("INSERT INTO auth_state (state_key, issuer, original_url) VALUES (?, ?, ?)", \
				(state_key, issuer['id'], orig_url))

		return self.send_answer(request, 'redirecting to issuer', code=302, location=location)

	@inlineCallbacks
	def answer_login(self, request):
		params = request.args
		orig_url = self.get_safe_redirect(qparam(params, 'orig_url') or request.getHeader('Referer'))
		issuer_url = qparam(params, 'issuer_url') or ''

		if not orig_url:
			returnValue(self.send_answer(request, 'missing orig_url', code=400))
		if (not issuer_url) or (not issuer_url.startswith('https://')):
			returnValue(self.send_answer(request, 'missing or unrecognized issuer_url', code=302, location= orig_url))
		issuer_url = self.normalize_issuer(issuer_url)

		issuer = db.cursor().execute("SELECT * FROM issuer WHERE issuer_url = ?", (issuer_url, )).fetchone()
		if not issuer:
			db.rollback()
			issuer = yield self.create_issuer(issuer_url)
		returnValue(self.basic_answer_login(request, issuer, orig_url))

	def answer_refresh(self, request):
		if not request.session_row:
			return self.answer_login(request)

		params = request.args
		orig_url = self.get_safe_redirect(qparam(params, 'orig_url') or request.getHeader('Referer'))
		if not orig_url:
			return self.send_answer(request, 'missing orig_url', code=400)

		db.cursor().execute("UPDATE session SET refresh_count = refresh_count + 1 WHERE id = ?", (request.session_row['id'], ))

		issuer = db.cursor().execute("SELECT * FROM issuer WHERE id = ?", (request.session_row['issuer'], )).fetchone()
		return self.basic_answer_login(request, issuer, orig_url)

	@inlineCallbacks
	def answer_code(self, request):
		params = request.args
		state_key = qparam(params, 'state')
		code = qparam(params, 'code')
		if not state_key or not code: # TODO: check for errors
			returnValue(self.send_answer(request, 'bad response from issuer', code=400))

		c = db.cursor()

		state_issuer = c.execute("SELECT auth_state.id AS auth_id, issuer.id as issuer_id, issuer.lifetime as issuer_lifetime, * "
				"FROM auth_state JOIN issuer ON auth_state.issuer = issuer_id WHERE state_key = ?", (state_key, )).fetchone()
		if not state_issuer:
			returnValue(self.send_answer(request, 'authorization transaction state not found', code=400))
		c.execute("DELETE FROM auth_state WHERE id = ?", (state_issuer['auth_id'], ))
		db.commit()

		client_id = state_issuer['client_id']
		client_secret = state_issuer['client_secret']
		basic_auth = (client_id, client_secret or '') if state_issuer['secret_basic'] else None
		query = dict(code=code, grant_type='authorization_code', redirect_uri=args.url + self.CODE)
		if not basic_auth:
			query.update(dict(client_id=client_id, client_secret=client_secret))
		tokenResponse, tokenBody = yield self.get_url(state_issuer['token_url'], basic_auth=basic_auth, query=query)
		if not tokenResponse:
			returnValue(self.send_answer(request, 'bad response from token endpoint', code=400))
		tokenAnswer = json.loads(tokenBody)
		if not tokenAnswer.get('id_token'):
			returnValue(self.send_answer(request, 'bad response from token endpoint', code=400)) # TODO: error? redirect to orig_url?

		id_token = tokenAnswer['id_token']
		try:
			claims, webid = yield self.check_id_token(id_token, state=state_key, issuer_row=state_issuer)
		except Exception as e:
			self.log_message("id_token validation failed: %s", e.message)
			returnValue(self.send_answer(request, "invalid id token: %s" % (e.message, ), code=400)) # TODO: what to do?
		
		# we're legit now
		if (request.session_webid != webid) or (request.session_row['issuer'] != state_issuer['issuer_id']):
			if request.session_row:
				self.log_message("delete session for <%s>", request.session_row['webid'])
				c.execute("DELETE FROM session WHERE id = ?", (request.session_row['id'], ))
				request.session_row = None
				request.session_webid = None

		now = long(time.time())
		lifetime = max(10, min(args.session_lifetime, qparam(params, 'expires_in') or inf, claims.get('exp', inf) - now))
		if request.session_row:
			c.execute("UPDATE session SET updated_on = ?, expires_on = ?, checked_on = ?, host = ?, " \
					"refresh_count = 0, refresh_token = ?, id_expires_on = ?" \
					"WHERE id = ?", \
					(now, now + request.session_row['lifetime'], now, self.get_client_addr(request), \
						tokenAnswer.get('refresh_token'), now + lifetime, request.session_row['id']))
			self.log_message("update session for <%s>", webid)
		else:
			c.execute("INSERT INTO session "
					"(expires_on, lifetime, cookie, issuer, host, webid, refresh_token, id_expires_on) " \
					"VALUES (?, ?, ?, ?, ?, ?, ?, ?)", \
					(now + args.session_lifetime, args.session_lifetime, random_token(), state_issuer['issuer_id'], \
						self.get_client_addr(request), webid, tokenAnswer.get('refresh_token'), now + lifetime))
			request.session_row = c.execute("SELECT * FROM session WHERE id = ?", (c.lastrowid, )).fetchone()
			request.session_webid = webid
			self.log_message("create session for <%s>", webid)

		new_expires_on = min(state_issuer['hard_exp_on'], now + state_issuer['issuer_lifetime'])
		c.execute("UPDATE issuer SET expires_on = ?, updated_on = ? WHERE id = ?", \
				(new_expires_on, now, state_issuer['issuer_id']))

		request.addCookie(self.COOKIE, request.session_row['cookie'], path="/", secure=True, httpOnly=True)
		returnValue(self.send_answer(request, 'redirecting to original url', code=302,
			location=state_issuer['original_url']
		))

	def answer_logout(self, request):
		if request.auth_cookie:
			if request.session_webid:
				self.log_message("log out <%s>", request.session_webid)
			db.cursor().execute("DELETE FROM session WHERE cookie = ?", (request.auth_cookie, ))
		orig_url = self.get_safe_redirect(qparam(request.args, 'orig_url') or request.getHeader('Referer'))
		if orig_url and 'POST' == request.method:
			return self.send_answer(request, code=302, location=orig_url)
		return self.send_answer(request, 'logged out')

	@inlineCallbacks
	def answer_webid_pop(self, request):
		yield succeed(None)
		other_headers = [('Access-Control-Allow-Origin', request.getHeader('Origin') or '*')]
		returnValue(self.send_answer(request, code=302, other_headers=other_headers, location='https://zenomt.zenomt.com/t.html#fragment'))

	@asyncResponse
	@inlineCallbacks
	def answer_async(self, f, request):
		try:
			d = request.notifyFinish()
			yield f(request)
			if not d.called:
				raise ValueError("async request didn't finish")
		except Exception as e:
			db.rollback()
			print traceback.format_exc()
			self.send_answer(request, code=500)

	def get_path(self, request):
		urlParts = urlparse.urlparse(request.path)
		path = urlParts.path
		if path.startswith(urlPathPrefix):
			path = path[len(urlPathPrefix):]
		return path

	def process_request(self, request):
		try:
			db.rollback()

			request.access_token_row = None
			request.auth_cookie = None
			request.session_row = None
			request.session_webid = None

			if not request.getHeader('Authorization'):
				request.auth_cookie = request.getCookie(self.COOKIE)
				request.session_row = db.cursor().execute("SELECT session.*, issuer.userinfo_url " \
						"FROM session JOIN issuer ON session.issuer = issuer.id WHERE cookie = ?", \
						(request.auth_cookie, )).fetchone() if request.auth_cookie else None
				request.session_webid = request.session_row['webid'] if request.session_row else None

			path = self.get_path(request)

			if   path == self.AUTHCHECK:
				return self.answer_async(self.answer_authcheck, request)
			elif path == self.LOGIN:
				return self.answer_async(self.answer_login, request)
			elif path == self.REFRESH:
				return self.answer_refresh(request)
			elif path == self.CODE:
				return self.answer_async(self.answer_code, request)
			elif path == self.LOGOUT:
				return self.answer_logout(request)
			elif path == self.WEBID_POP:
				return self.answer_async(self.answer_webid_pop, request)

			if 'GET' == request.method:
				return self.answer_file(request, path)

			return self.send_answer(request, 'bad request', code=405)
		except Exception as e:
			db.rollback()
			print traceback.format_exc()
			request.setResponseCode(500)
			return ''

	def render_POST(self, request):
		return self.process_request(request)

	def render_GET(self, request):
		return self.process_request(request)


db.executescript("""
PRAGMA foreign_keys = on;

CREATE TABLE IF NOT EXISTS issuer (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	created_on    INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on    INTEGER DEFAULT (strftime('%s', 'now', '+2 days')),
	updated_on    INTEGER DEFAULT (strftime('%s', 'now')),
	hard_exp_on   INTEGER DEFAULT (strftime('%s', 'now', '+2 days')),
	lifetime      INTEGER DEFAULT 172800,
	issuer_url    TEXT UNIQUE NOT NULL,
	client_id     TEXT NOT NULL,
	client_secret TEXT,
	userinfo_url  TEXT,
	auth_url      TEXT,
	token_url     TEXT,
	jwks_url      TEXT,
	secret_post   BOOLEAN,
	secret_basic  BOOLEAN
);

CREATE TABLE IF NOT EXISTS session (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	created_on    INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on    INTEGER DEFAULT (strftime('%s', 'now', '+1 day')),
	updated_on    INTEGER DEFAULT (strftime('%s', 'now')),
	checked_on    INTEGER DEFAULT (strftime('%s', 'now')),
	lifetime      INTEGER DEFAULT 86400,
	cookie        TEXT UNIQUE NOT NULL,
	issuer        INTEGER NOT NULL REFERENCES issuer(id) ON DELETE CASCADE,
	refresh_count INTEGER DEFAULT 0,
	host          TEXT,
	webid         TEXT,
	refresh_token TEXT,
	id_expires_on INTEGER
);

CREATE TABLE IF NOT EXISTS auth_state (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	created_on   INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on   INTEGER DEFAULT (strftime('%s', 'now', '+10 minutes')),
	state_key    TEXT UNIQUE NOT NULL,
	issuer       INTEGER NOT NULL REFERENCES issuer(id) ON DELETE CASCADE,
	original_url TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_token (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	created_on   INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on   INTEGER DEFAULT (strftime('%s', 'now', '+1 hour')),
	host         TEXT,
	access_token TEXT UNIQUE NOT NULL,
	webid        TEXT NOT NULL,
	appid        TEXT
);

CREATE TABLE IF NOT EXISTS token_challenge (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	created_on   INTEGER DEFAULT (strftime('%s', 'now')),
	expires_on   INTEGER DEFAULT (strftime('%s', 'now', '+10 minutes')),
	nonce        TEXT UNIQUE NOT NULL,
	uri          TEXT NOT NULL,
	host         TEXT
);

""")

db.commit()

prepare_locations()
if args.debug:
	print "locations", locations

do_cleanup() # async
factory = server.Site(AuthResource(), logFormatter=proxiedLogFormatter)
reactor.listenTCP(args.port, factory, interface=args.address)
reactor.run()
