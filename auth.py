#! /usr/bin/env python --

#  MIT License
#  
#  Copyright (c) 2019 Michael Thornburgh
#  
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is furnished
#  to do so, subject to the following conditions:
#  
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#  
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.


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
import rsa
import sqlite3
import sys
import thread
import time
import traceback
import urllib
import urllib2
import urlparse

from fnmatch import fnmatchcase
from jose import jwt, jws

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue, Deferred, succeed
from twisted.python import log
from twisted.web import resource, server
from twisted.web.client import readBody, Agent, ContentDecoderAgent, FileBodyProducer, GzipDecoder, RedirectAgent
from twisted.web.http import proxiedLogFormatter
from twisted.web.http_headers import Headers


RANDOM_TOKEN_LENGTH = 30
PROOF_TOKEN_APP_AUTHORIZATIONS = "app_authorizations"
MAX_APP_AUTHORIZATION_URIS = 4

NONE_TAG     = binascii.hexlify(os.urandom(RANDOM_TOKEN_LENGTH))
NONE_APP_TAG = NONE_TAG + "-app"

ACL_MODE           = rdflib.URIRef('http://www.w3.org/ns/auth/acl#mode')
ACL_APP            = rdflib.URIRef('http://www.w3.org/ns/auth/acl#app')
ACL_ORIGIN         = rdflib.URIRef('http://www.w3.org/ns/auth/acl#origin')
ACL_DEFAULT        = rdflib.URIRef('http://www.w3.org/ns/auth/acl#default')
ACL_AGENT          = rdflib.URIRef('http://www.w3.org/ns/auth/acl#agent')
ACL_AGENTCLASS     = rdflib.URIRef('http://www.w3.org/ns/auth/acl#agentClass')
ACL_AGENTGROUP     = rdflib.URIRef('http://www.w3.org/ns/auth/acl#agentGroup')
ACL_AUTHORIZATION  = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Authorization')
ACL_SEARCH         = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Search')
ACL_READ           = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Read')
ACL_WRITE          = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Write')
ACL_APPEND         = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Append')
ACL_CONTROL        = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Control')
ACL_OTHER          = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Other')
FOAF_AGENT         = rdflib.URIRef('http://xmlns.com/foaf/0.1/Agent')
SOLID_OIDCISSUER   = rdflib.URIRef('http://www.w3.org/ns/solid/terms#oidcIssuer')
VCARD_HASMEMBER    = rdflib.URIRef('http://www.w3.org/2006/vcard/ns#hasMember')

ACL_AUTHENTICATEDAGENT = rdflib.URIRef('http://www.w3.org/ns/auth/acl#AuthenticatedAgent')
ACL_ACCESSTOCLASS      = rdflib.URIRef('http://www.w3.org/ns/auth/acl#accessToClass')
ACL_EXCLUDEAGENT       = rdflib.URIRef('http://www.w3.org/ns/auth/acl#excludeAgent')
ACL_EXCLUDEAGENTGROUP  = rdflib.URIRef('http://www.w3.org/ns/auth/acl#excludeAgentGroup')
ACL_EXCLUDEORIGIN      = rdflib.URIRef('http://www.w3.org/ns/auth/acl#excludeOrigin')
ACL_TAG                = rdflib.URIRef('http://www.w3.org/ns/auth/acl#tag')
ACL_RESOURCE           = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Resource')
ACL_SUBRESOURCE        = rdflib.URIRef('http://www.w3.org/ns/auth/acl#SubResource')
ACL_CONTAINER          = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Container')
ACL_SUBCONTAINER       = rdflib.URIRef('http://www.w3.org/ns/auth/acl#SubContainer')
ACL_DOCUMENT           = rdflib.URIRef('http://www.w3.org/ns/auth/acl#Document')
RDFS_SEEALSO           = rdflib.URIRef('http://www.w3.org/2000/01/rdf-schema#seeAlso')

# support for user-controlled app tags
ACL_APPAUTHORIZATION   = rdflib.URIRef('http://www.w3.org/ns/auth/acl#AppAuthorization')
ACL_APPAUTHORIZATIONS  = rdflib.URIRef('http://www.w3.org/ns/auth/acl#appAuthorizations')
ACL_RESOURCESERVER     = rdflib.URIRef('http://www.w3.org/ns/auth/acl#resourceServer')
ACL_REALM              = rdflib.URIRef('http://www.w3.org/ns/auth/acl#realm')
ACL_TAGMODE            = rdflib.URIRef('http://www.w3.org/ns/auth/acl#tagMode')

XSD_TRUE  = rdflib.term.Literal(True)
XSD_FALSE = rdflib.term.Literal(False)

WILDCARD_LITERAL = rdflib.term.Literal("*")

PERMISSION_FLAGS = { ACL_SEARCH: 1, ACL_WRITE: 2, ACL_READ: 4, ACL_APPEND: 16, ACL_CONTROL: 32, ACL_OTHER: 32768 }

# when making a token, ACL_WRITE includes ACL_APPEND
PERMISSION_FLAGS_TOKEN = PERMISSION_FLAGS.copy()
PERMISSION_FLAGS_TOKEN[ACL_WRITE] = PERMISSION_FLAGS[ACL_WRITE] | PERMISSION_FLAGS[ACL_APPEND]
# and any flag implies ACL_SEARCH
for k in PERMISSION_FLAGS_TOKEN:
	PERMISSION_FLAGS_TOKEN[k] |= PERMISSION_FLAGS[ACL_SEARCH]

DEFAULT_NS = {
	"acl": rdflib.URIRef('http://www.w3.org/ns/auth/acl#'),
	"foaf": rdflib.URIRef('http://xmlns.com/foaf/0.1/'),
	"rdfs": rdflib.URIRef('http://www.w3.org/2000/01/rdf-schema#'),
	"solid": rdflib.URIRef('http://www.w3.org/ns/solid/terms#'),
	"vcard": rdflib.URIRef('http://www.w3.org/2006/vcard/ns#')
}

DEFAULT_NS_TTL = """
@prefix acl: <http://www.w3.org/ns/auth/acl#> .
@prefix foaf: <http://xmlns.com/foaf/0.1/> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix solid: <http://www.w3.org/ns/solid/terms#> .
@prefix vcard: <http://www.w3.org/2006/vcard/ns#> .
"""

METHODS_READ   = ["OPTIONS", "GET", "QUERY", "HEAD", "TRACE", "PROPFIND", "SEARCH"]
METHODS_WRITE  = ["PUT", "POST", "DELETE", "PATCH", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]
METHODS_APPEND = ["PUT", "POST", "PATCH", "PROPPATCH", "MKCOL"]

inf = float('inf')

def expand_perms(mode_mask):
	return map(lambda x: x[0], filter(lambda y: y[1] & mode_mask, PERMISSION_FLAGS.items()))

def ensure(v, msg=''):
	if not v:
		raise ValueError(msg)

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
	port = urlparts.port
	if (not port) or (port == { 'http':80, 'https':443 }.get(scheme)):
		port = ''
	else:
		port = ':%s' % (port, )
	return ('%s://%s%s' % (scheme, urlparts.hostname or '', port)).lower()

def canonical_origin(uri):
	return canonical_origin_parsed(urlparse.urlparse(uri))

def is_suburi(base, uri):
	return '/../' not in uri and uri.startswith(base if base.endswith('/') else base + '/')

def load_local_graph(path, publicID, format=None):
	try:
		debug_log("loading %s", path)
		rv = rdflib.Graph()
		format = format or rdflib.util.guess_format(path) or 'turtle'
		data = DEFAULT_NS_TTL if format in ('turtle', 'n3') else ''
		data += open(path, 'rb').read()
		rv.parse(data=data, format=format, publicID=publicID)
		return rv
	except Exception as e:
		print "error loading RDF <%s> (%s)" % (publicID, path)
		raise e

def get_rsa_jwks_from_card(card, webid):
	keys = []
	initBindings = dict(webid=rdflib.URIRef(webid))
	ns = { 'cert': rdflib.URIRef('http://www.w3.org/ns/auth/cert#') }
	qresult = card.query("""
SELECT ?exponent ?modulus WHERE {
  ?key   a              cert:RSAPublicKey;
         cert:exponent  ?exponent;
         cert:modulus   ?modulus.
  ?webid cert:key ?key.
}""", initBindings=initBindings, initNs=ns)
	for exponent, modulus in qresult:
		if exponent.datatype == rdflib.XSD.integer:
			e = b64u_encode(rsa.transform.int2bytes(exponent.value))
		else:
			continue # exponent must be an integer
		if modulus.datatype == rdflib.XSD.hexBinary:
			n_bytes = binascii.unhexlify(str(modulus))
		elif modulus.datatype == rdflib.XSD.base64Binary:
			n_bytes = base64.b64decode(str(modulus))
		else:
			continue # modulus wrong format
		n = b64u_encode(n_bytes)
		keys.append(dict(e=e, n=n, kty="RSA"))
	return dict(keys=keys)

def get_claim_list(claims, key, default=None):
	if claims.has_key(key):
		rv = claims[key]
		return rv if isinstance(rv, list) else [unicode(rv)]
	return default

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
parser.add_argument('-l', '--session-lifetime', type=int, help="lifetime for sessions (default %(default)s)", default=86400)
parser.add_argument('-t', '--token-lifetime', type=int, help="lifetime for access tokens (default %(default)s)", default=1800)
parser.add_argument('-m', '--min-token-lifetime', type=int, help="minimum lifetime for access tokens (default %(default)s)", default=180)
parser.add_argument('-i', '--cleanup-interval', type=float, default=10.,
	help="interval between database cleanup runs (default %(default).3f)")
parser.add_argument('-r', '--max-refreshes', default=1, type=int,
	help="maximum failed refreshes before requiring a login (default %(default)s)")
parser.add_argument('--acl-suffix', default='.acl',
	help="filename suffix for access control files (default %(default)s)")
parser.add_argument('--http-timeout', default=5., type=float,
	help="timeout for HTTP requests to other servers (default %(default).3f)")
parser.add_argument('--stale-period', default=30., type=float,
	help="refresh period for cached graphs from other servers (default %(default).3f)")
parser.add_argument('--cache-expire', default=900., type=float,
	help="forget cached graphs older than this (default %(default).3f)")
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

# locations = [ { origin, prefix, root, base, }, ... ]
locations = []
config_file = json.loads(open(args.config_file, 'rb').read())

fetch_graph_cache = {}     # { uri: { etag, stale_at, graph }, ... }
fetch_graph_requests = {}  # { uri: [ deferred, ... ], ... }

agent = ContentDecoderAgent(RedirectAgent(Agent(reactor)), [(b"gzip", GzipDecoder)])


def debug_log(fmt, *s):
	if args.debug:
		print fmt % s

def prepare_locations():
	for prefix, root in config_file['locations'].items():
		urlparts = urlparse.urlparse(prefix)
		origin = canonical_origin_parsed(urlparts)
		prefix = urlparts.path
		prefix = prefix if prefix[-1] == '/' else prefix + '/'
		root = root if root[-1] == '/' else root + '/'
		locations.append(dict(origin=origin, prefix=prefix, root=root, base=origin + prefix))
	locations.sort(reverse=True, key=lambda x: x['prefix'].count('/'))

def find_location(uri): # returns { (location), path, query }
	urlparts = urlparse.urlparse(uri)
	origin = canonical_origin_parsed(urlparts)
	path = posixpath.normpath(urlparts.path)
	for each in locations:
		prefix = each['prefix']
		if each['origin'] == origin:
			if (prefix == path[:len(prefix)]) or (prefix[:-1] == path):
				rv = dict(path=path[len(prefix):], query=urlparts.query)
				rv.update(each)
				return rv

def try_find_local_graph(uri):
	location = find_location(uri)
	if location and not location['query']:
		path = location['root'] + location['path']
		if posixpath.isfile(path):
			debug_log("trying to load local graph <%s> (%s)", uri, path)
			return load_local_graph(path, uri)

def load_local_graph_ext(path, publicID, format=None):
	rv = load_local_graph(path, publicID, format)
	for see_also in list(rv.objects(rdflib.URIRef(publicID), RDFS_SEEALSO)):
		otherGraph = try_find_local_graph(unicode(see_also))
		if not otherGraph:
			raise ValueError("couldn't find rdfs:seeAlso graph %s locally" % (see_also, ))
		rv += otherGraph
	return rv

def expire_fetch_graph_cache():
	now = time.time()
	for k in list(fetch_graph_cache.keys()):
		if fetch_graph_requests.get(k):
			continue
		entry = fetch_graph_cache[k]
		if (entry['stale_at'] + args.cache_expire < now) or \
				(not entry['etag'] and (entry['stale_at'] < now)):
			del fetch_graph_cache[k]
			debug_log("expire cached graph <%s>", k)

@inlineCallbacks
def fetch_graph_cached_shared(uri):
	debug_log("fetch graph shared <%s>", uri)
	if isinstance(uri, unicode):
		uri = uri.encode('utf8')
	uri = urlparse.urldefrag(uri)[0]
	entry = fetch_graph_cache.get(uri)
	if entry and (entry['stale_at'] > time.time()):
		debug_log("<%s> fresh in cache", uri)
		returnValue(entry['graph'])
	request_queue = fetch_graph_requests.get(uri)
	if request_queue is None:
		request_queue = []
		fetch_graph_requests[uri] = request_queue
		try:
			headers = Headers()
			if entry and entry['etag']:
				headers.addRawHeader('If-None-Match', entry['etag'])
			request = agent.request(b'GET', uri, headers=headers)
			request.addTimeout(args.http_timeout, reactor)
			response = yield request
			body = yield readBody(response)

			if 304 == response.code:
				entry['stale_at'] = time.time() + args.stale_period
				graph = entry['graph']
				debug_log("<%s> 304 Not Modified", uri)
			elif 200 != response.code:
				raise ValueError("bad response from <%s>: %s" % (uri, response.code))
			else:
				graph = rdflib.Graph()
				format = response.headers.getRawHeaders("content-type", [None])[0]
				format = re.split(r' *; *', format)[0] if format else None
				etag = response.headers.getRawHeaders("ETag", [None])[0]
				graph.parse(data=body, format=format, publicID=uri)
				fetch_graph_cache[uri] = dict(etag=etag, graph=graph, stale_at=time.time() + args.stale_period)
				debug_log("<%s> newly loaded", uri)

			del fetch_graph_requests[uri]
			for each in request_queue:
				each.callback(graph)

			returnValue(graph)

		except Exception as e:
			del fetch_graph_requests[uri]
			for each in request_queue:
				each.errback(e)
			raise e
	else:
		d = Deferred()
		request_queue.append(d)
		graph = yield d
		debug_log("<%s> from shared download", uri)
		returnValue(graph)

@inlineCallbacks
def find_local_or_fetch_graph(uri):
	returnValue(try_find_local_graph(uri) or (yield fetch_graph_cached_shared(uri)))

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
			expire_fetch_graph_cache()
		except sqlite3.OperationalError:
			db.rollback()
			print traceback.format_exc()
			print "will retry in", args.cleanup_interval
		except Exception as e:
			print "exception in do_cleanup(), aborting task"
			print traceback.format_exc()
			db.rollback()
			return
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

	def debug_log(self, fmt, *s):
		if args.debug:
			self.log_message(fmt, *s)

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
		if url.startswith(args.url) or not find_location(url):
			return None
		return url

	def normalize_issuer(self, url):
		parts = urlparse.urlparse(url)
		path = '.' if parts.path.endswith('/') else parts.path + '/'
		return urlparse.urljoin(url, path)

	def send_answer(self, request, body='', code=200, content_type='text/plain', other_headers=[], cache=False, location=None):
		if isinstance(body, unicode):
			body = body.encode('utf8')
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

	@inlineCallbacks
	def check_acl_for_perm(self, aclGraph, origin, webid, appid, app_origin, tagModes, permission, isDirectory, inherited=False):
		tags = set(map(lambda x: x['tag'], filter(lambda y: y['mode_mask'] & PERMISSION_FLAGS.get(permission, 0), tagModes)))
		def _filter_by_resource_type(authorizations):
			if isDirectory and inherited:
				resourceClasses = set((ACL_RESOURCE, ACL_CONTAINER, ACL_SUBRESOURCE, ACL_SUBCONTAINER))
			elif isDirectory and not inherited:
				resourceClasses = set((ACL_RESOURCE, ACL_CONTAINER))
			else:
				resourceClasses = set((ACL_RESOURCE, ACL_SUBRESOURCE, ACL_DOCUMENT))

			def _filterp(auth):
				if inherited:
					aclDefaults = list(aclGraph.objects(auth, ACL_DEFAULT))
					if (not aclDefaults) or (XSD_FALSE in aclDefaults):
						return False
				accessToClasses = set(aclGraph.objects(auth, ACL_ACCESSTOCLASS)) or set((ACL_RESOURCE, )) # what about acl:accessTo?
				return resourceClasses.intersection(accessToClasses)

			return filter(_filterp, authorizations)

		def _by_app_tags_p(auth):
			if app_origin and any(map(lambda x: canonical_origin(x) == app_origin, aclGraph.objects(auth, ACL_EXCLUDEORIGIN))):
				return False
			for each in list(aclGraph.objects(auth, ACL_TAG)) or [NONE_TAG]:
				if any(map(lambda x: fnmatchcase(each, x) or fnmatchcase(x, each), tags)):
					return True
			if appid:
				for each in aclGraph.objects(auth, ACL_ORIGIN):
					if ("*" == unicode(each)) or (canonical_origin(each) == app_origin):
						return True
				for each in aclGraph.objects(auth, ACL_APP):
					if appid.startswith(each):
						return True

		# if no [? acl:mode acl:Search] in aclGraph, assume search is granted for all
		if (permission == ACL_SEARCH) and not any(aclGraph.subjects(ACL_MODE, ACL_SEARCH)):
			returnValue(self.PERM_OK)

		authorizations = _filter_by_resource_type(aclGraph.subjects(ACL_MODE, permission))
		if permission == ACL_APPEND:
			authorizations.extend(_filter_by_resource_type(aclGraph.subjects(ACL_MODE, ACL_WRITE)))
		anyAuths = bool(authorizations)

		tags = tags or [NONE_APP_TAG]
		authorizations = filter(_by_app_tags_p, authorizations)

		if not authorizations:
			if anyAuths:
				returnValue(self.PERM_NOTYOU if webid else self.PERM_AUTH)
			returnValue(self.PERM_NONE)

		if not webid:
			if any(map(lambda x: (x, ACL_AGENTCLASS, FOAF_AGENT) in aclGraph, authorizations)):
				returnValue(self.PERM_OK)
			returnValue(self.PERM_AUTH)

		@inlineCallbacks
		def _member_of_any_group(auth, predicate):
			for group in aclGraph.objects(auth, predicate):
				try:
					if (group, None, None) in aclGraph:
						groupGraph = aclGraph
					else:
						groupGraph = yield find_local_or_fetch_graph(unicode(group))
					if (group, VCARD_HASMEMBER, webid) in groupGraph:
						returnValue(True)
				except Exception as e:
					print "error loading group <%s>: %s" % (unicode(group), `e`)
					if predicate == ACL_EXCLUDEAGENTGROUP:
						print "error loading exclusion group, denying access"
						returnValue(True)
			returnValue(False)

		for auth in authorizations:
			if (auth, ACL_EXCLUDEAGENT, webid) in aclGraph:
				continue
			isExcludedGroupMember = yield _member_of_any_group(auth, ACL_EXCLUDEAGENTGROUP)
			if isExcludedGroupMember:
				continue

			if (auth, ACL_AGENTCLASS, FOAF_AGENT) in aclGraph:
				returnValue(self.PERM_OK)
			if (auth, ACL_AGENTCLASS, ACL_AUTHENTICATEDAGENT) in aclGraph:
				returnValue(self.PERM_OK)
			if (auth, ACL_AGENT, webid) in aclGraph:
				returnValue(self.PERM_OK)
			isGroupMember = yield _member_of_any_group(auth, ACL_AGENTGROUP)
			if isGroupMember:
				returnValue(self.PERM_OK)

		returnValue(self.PERM_NOTYOU)

	@inlineCallbacks
	def check_permission(self, method, uri, webid, appid, tagModes):
		location = find_location(uri) # { origin, prefix, root, base, path, query }
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
		origin = location['origin']

		for dir_ in path:
			current_dir = posixpath.join(current_dir, dir_ )
			aclFilename = posixpath.join(current_dir, args.acl_suffix)
			aclURI = urlparse.urljoin(aclURI, (dir_ or '.') + '/' + args.acl_suffix)
			if posixpath.isfile(aclFilename):
				cachedReadable = False
				lastACL = load_local_graph_ext(aclFilename, aclURI, format='turtle')
				reason = yield self.check_acl_for_perm(lastACL, origin, webid, appid, app_origin, tagModes, ACL_SEARCH, True)
				if reason is not self.PERM_OK:
					returnValue((reason, None))
			elif not lastACL:
				raise ValueError("missing root ACL (%s) <%s>?" % (aclFilename, aclURI))
			elif not cachedReadable:
				reason = yield self.check_acl_for_perm(lastACL, origin, webid, appid, app_origin, tagModes, ACL_SEARCH, True, inherited=True)
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
				lastACL = load_local_graph_ext(aclFilename, aclURI, format='turtle')
				using_inherited = False
			else:
				using_inherited = True

		check_for = lambda perm: self.check_acl_for_perm(lastACL, origin, webid, appid, app_origin, tagModes, perm, not leaf, inherited=using_inherited)

		if   need_control:
			mode = ACL_CONTROL
			reason = yield check_for(ACL_CONTROL)
			if (reason is not self.PERM_OK) and (not using_inherited) and (method in METHODS_READ):
				mode = ACL_READ
				reason = yield check_for(ACL_READ)
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
				request.app_tags = db.cursor().execute("SELECT * FROM app_tag WHERE access_token_id = ?", (request.access_token_row['id'], )).fetchall()
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
		appid = request.access_token_row['appid'] if request.access_token_row else request.getHeader('Origin') or canonical_origin(uri)
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
				www_authenticate.append('token_pop_endpoint="%s"' % (args.url + self.WEBID_POP, ))
				www_authenticate.append('nonce="%s"' % (self.make_token_challenge(uri, request), ))
				other_headers.append(('WWW-Authenticate', ", ".join(www_authenticate)))
			return self.send_answer(request, code=code, other_headers=other_headers)

		if status == self.STATUS_BAD_TOKEN:
			returnValue(send_auth_answer(401, authMode=self.MODE_TOKEN))

		perm, mode = yield self.check_permission(method, uri, webid, appid, request.app_tags)

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
			self.debug_log("get_url %s", url)
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
		provided_issuer_url = issuer_url
		def suburl(url):
			return urlparse.urljoin(issuer_url, url) if url else None

		@inlineCallbacks
		def get_config():
			response, body = yield self.get_url(suburl('.well-known/openid-configuration'))
			returnValue(json.loads(body) if 200 == response.code else {})

		try:
			db.rollback()
			config = yield get_config()
			if 'issuer' in config and not (issuer_url == self.normalize_issuer(config['issuer'])):
				print "issuer %s -> %s" % (issuer_url, config['issuer'])
				issuer_url = self.normalize_issuer(config['issuer'])
				config = yield get_config()
				if 'issuer' in config and not (issuer_url == self.normalize_issuer(config['issuer'])):
					print "issuer %s is misconfigured" % (issuer_url, )
					returnValue(None)
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
					"(expires_on, hard_exp_on, lifetime, issuer_url, issuer_actual, client_id, client_secret, userinfo_url, "
					"    auth_url, token_url, jwks_url, secret_post, secret_basic) "
					"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
						now + lifetime, hard_expiration, lifetime,
						provided_issuer_url,
						config.get('issuer'),
						registration.get('client_id'), registration.get('client_secret'),
						suburl(config.get('userinfo_endpoint')),
						suburl(config.get('authorization_endpoint')),
						suburl(config.get('token_endpoint')),
						suburl(config.get('jwks_uri')),
						"client_secret_post" in auth_modes, "client_secret_basic" in auth_modes
					))
			rv = c.execute("SELECT * FROM issuer WHERE id = ?", (c.lastrowid, )).fetchone()
			db.commit()
			print "created issuer %s (%s)" % (provided_issuer_url, config.get('issuer') or '')
			returnValue(rv)
		except Exception as e:
			print traceback.format_exc()
			db.rollback()
			returnValue(None)

	def nonce_from_state(self, state):
		return b64u_sha256(state)[:16]

	@inlineCallbacks
	def load_json(self, url):
		response, body = yield self.get_url(url)
		if 200 != response.code:
			raise ValueError("unexpected esponse code %d for <%s>", (response.code, url))
		returnValue(json.loads(body))

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

	def ensure_audience_member(self, claims, expected, check_azp=True):
		aud = claims['aud']
		aud = aud if isinstance(aud, list) else [aud]
		if expected not in aud:
			raise ValueError("audience missing expected member")
		if check_azp and claims.get('azp') and (claims['azp'] != expected):
			raise ValueError("authorized party mismatch")

	def ensure_valid_issuer(self, card, webid, issuer_url):
		webid_ref = rdflib.URIRef(webid)
		issuer_ref = rdflib.URIRef(issuer_url)

		if (webid_ref, SOLID_OIDCISSUER, None) in card:
			if (webid_ref, SOLID_OIDCISSUER, issuer_ref) not in card:
				raise ValueError("webid <%s> lists issuers but not <%s>" % (webid, issuer_url))
		else:
			webid_parts = urlparse.urlparse(webid)
			issuer_parts = urlparse.urlparse(issuer_url)
			if (webid_parts.hostname != issuer_parts.hostname) and not webid_parts.hostname.endswith('.' + issuer_parts.hostname):
				raise ValueError("webid <%s> hostname is not a subdomain of issuer <%s> hostname" % (webid, issuer_url))

	@inlineCallbacks
	def check_id_token(self, raw_token, state, issuer_row):
		enc_header, enc_claims, enc_sig = raw_token.split('.')
		claims = json.loads(b64u_decode(enc_claims))
		webid = claims.get('webid') or claims.get('sub') or ''
		issuer_url = issuer_row['issuer_actual'] or issuer_row['issuer_url']
		nonce = claims.get('nonce') or ''
		webid_parts = urlparse.urlparse(webid)
		my_client = issuer_row['client_id']

		self.debug_log("check_id_token %s", raw_token)

		if not webid:
			raise ValueError("id_token doesn't identify a webid")

		if self.normalize_issuer(claims.get("iss")) != self.normalize_issuer(issuer_url):
			raise ValueError("id_token doesn't claim issuer")

		self.ensure_audience_member(claims, my_client)

		if claims.get("exp", 0) < time.time():
			raise ValueError("id_token expires in the past")

		if nonce != self.nonce_from_state(state):
			raise ValueError("invalid nonce")
		if ('https' != webid_parts.scheme):
			raise ValueError("webid scheme is not https")

		card = yield self.load_graph(webid)
		self.ensure_valid_issuer(card, webid, issuer_url)

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
			return self.answer_async(self.answer_login, request)

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

	def _send_token_answer(self, request, access_token=None, expires_in=None, error=None, error_description=None, tags=None):
		redirect_uri = qparam(request.args, 'redirect_uri')
		state = qparam(request.args, 'state')
		code = 400 if error else 200
		rv = {}
		if access_token:
			rv['access_token'] = access_token
			rv['expires_in'] = expires_in
			rv['token_type'] = 'Bearer'
			if tags:
				rv['x_tags'] = tags
		if state:
			rv['state'] = state
		if error:
			rv['error'] = error
			rv['error_description'] = error_description
		if redirect_uri:
			return self.send_answer(request, code=302, location=redirect_uri + '#' + urlencode(rv))
		other_headers = [('Access-Control-Allow-Origin', request.getHeader('Origin') or '*')]
		return self.send_answer(request, code=code, body=json.dumps(rv, indent=4),
			content_type='application/json', other_headers=other_headers)

	def _compare_uris(self, uri1, uri2):
		parts1 = urlparse.urlparse(uri1)
		parts2 = urlparse.urlparse(uri2)

		return (canonical_origin_parsed(parts1) == canonical_origin_parsed(parts2)) and \
			(parts1.path == parts2.path) and \
			(parts1.query == parts2.query)

	@inlineCallbacks
	def load_app_tags(self, proof_claims, card, webid, appid, origin):
		webid = rdflib.URIRef(webid)
		app_origin = canonical_origin(appid)
		realm = rdflib.term.Literal(args.url)
		rv = {}
		app_authorization_uris = get_claim_list(proof_claims, PROOF_TOKEN_APP_AUTHORIZATIONS, [])[:MAX_APP_AUTHORIZATION_URIS]
		for app_authorization_uri in app_authorization_uris:
			try:
				if any(map(lambda x: is_suburi(x, app_authorization_uri), card.objects(webid, ACL_APPAUTHORIZATIONS))):
					authGraph = yield self.load_graph(app_authorization_uri)
					auth = rdflib.URIRef(app_authorization_uri)
					for server in authGraph.objects(auth, ACL_RESOURCESERVER):
						wildcardOrigin = (server, ACL_ORIGIN, WILDCARD_LITERAL) in authGraph
						forMyOrigin = any(map(lambda x: canonical_origin(x) == origin, authGraph.objects(server, ACL_ORIGIN)))
						if (not wildcardOrigin) and (not forMyOrigin):
							continue
						if ((server, ACL_REALM, None) in authGraph) and ((server, ACL_REALM, realm) not in authGraph):
							continue
						if (not any(map(lambda x: canonical_origin(x) == app_origin, authGraph.objects(auth, ACL_ORIGIN)))) and \
								(not any(map(lambda x: unicode(x).startswith(appid), authGraph.objects(auth, ACL_APP)))):
							continue
						for tagMode in authGraph.objects(auth, ACL_TAGMODE):
							mode_mask = reduce(lambda a, x: a | PERMISSION_FLAGS_TOKEN.get(x, 0), authGraph.objects(tagMode, ACL_MODE), 0)
							for tag in authGraph.objects(tagMode, ACL_TAG):
								tag = unicode(tag)
								if (not forMyOrigin) and (('*' in tag) or ('?' in tag)):
									continue
								rv[tag] = rv.get(tag, 0) | mode_mask
			except Exception as e:
				print "exception loading app tags (ignoring)"
				print traceback.format_exc()
		returnValue(rv)

	@inlineCallbacks
	def answer_webid_pop(self, request):
		trusted_algorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
		params = request.args
		proof_token = qparam(params, 'proof_token')
		try:
			proof_claims = jwt.get_unverified_claims(proof_token)
			ensure(all([proof_claims[i] for i in ["aud", "nonce", "sub", "iss"]]))
			id_token = proof_claims['sub']
			id_token_claims = jwt.get_unverified_claims(id_token)
			ensure(all([id_token_claims[i] for i in ["aud", "exp", "cnf", "sub", "iss"]]))
			proof_key = id_token_claims['cnf']['jwk']

			uri = proof_claims['aud']
			uri = uri[0] if isinstance(uri, list) else uri

			webid = id_token_claims.get('webid') or id_token_claims['sub']
			ensure(':' in webid, "couldn't find webid in id_token")
			id_token_issuer = id_token_claims['iss']

			jws.verify(proof_token, proof_key, algorithms=trusted_algorithms)
			self.ensure_audience_member(id_token_claims, proof_claims['iss'], check_azp=False)
			now = time.time()
			if proof_claims.has_key('exp'):
				ensure(proof_claims['exp'] > now, "proof_token expired")
				ensure(proof_claims['exp'] <= id_token_claims['exp'], "proof_token expires after id_token")

			c = db.cursor()
			challenge_row = c.execute("SELECT * FROM token_challenge WHERE nonce = ?", (proof_claims['nonce'], )).fetchone()
			if not challenge_row:
				raise ValueError("challenge nonce not found")
			c.execute("DELETE FROM token_challenge WHERE id = ?", (challenge_row['id'], ))
			db.commit()

			if not self._compare_uris(uri, challenge_row['uri']):
				raise ValueError("nonce wasn't issued for URI")

			card = yield self.load_graph(webid)
			self.ensure_valid_issuer(card, webid, id_token_issuer)
			if id_token_issuer == 'https://self-issued.me':
				jwks = get_rsa_jwks_from_card(card, webid)
				if not jwks:
					raise ValueError("self-issued id_token but webid doesn't list any valid cert:RSAPublicKeys")
				jws.verify(id_token, jwks, algorithms=["RS256"]) # only RS256 allowed for self-issued
			else:
				normalized_issuer = self.normalize_issuer(id_token_issuer)
				iss_config = yield self.load_json(normalized_issuer + '.well-known/openid-configuration')
				actual_issuer = iss_config.get('issuer') or id_token_issuer
				normalized_issuer = self.normalize_issuer(actual_issuer)
				if 'jwks_uri' not in iss_config:
					raise ValueError("issuer <%s> config doesn't list a JWKS URI" % (id_token_issuer, ))
				jwks = yield self.load_json(urlparse.urljoin(normalized_issuer, iss_config['jwks_uri']))
				jws.verify(id_token, jwks, algorithms=trusted_algorithms)

			appid = proof_claims['iss']
			appid = appid if ':' in appid else "unknown:"

			tagModes = yield self.load_app_tags(proof_claims, card, webid, appid, canonical_origin(uri))

			now = long(time.time())
			token_expires_on = long(max(now + args.min_token_lifetime, min(now + args.token_lifetime, proof_claims['exp'])))
			expires_in = long(token_expires_on - now)
			access_token = random_token()

			c = db.cursor()
			c.execute("INSERT INTO access_token (expires_on, host, access_token, webid, appid) VALUES (?, ?, ?, ?, ?)",
				(token_expires_on, self.get_client_addr(request), access_token, webid, appid))
			access_token_id = c.lastrowid

			tags = {}
			for tag, mode_mask in tagModes.items():
				if mode_mask:
					c.execute("INSERT INTO app_tag (access_token_id, tag, mode_mask) VALUES (?, ?, ?)", (access_token_id, tag, mode_mask))
					tags[tag] = expand_perms(mode_mask)

			db.commit()

			print "issue token to: <%s> appid: <%s> lifetime: %s tags: %s" % (webid, appid, expires_in, json.dumps(tags))
			returnValue(self._send_token_answer(request, access_token=access_token, expires_in=expires_in, tags=tags))
		except Exception as e:
			print traceback.format_exc()
			returnValue(self._send_token_answer(request, error="invalid_request", error_description=`e`))

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
			request.app_tags = []

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
	issuer_actual TEXT,
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

CREATE TABLE IF NOT EXISTS app_tag (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	access_token_id INTEGER NOT NULL REFERENCES access_token(id) ON DELETE CASCADE,
	tag             TEXT NOT NULL,
	mode_mask       INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS app_tag_token ON app_tag ( access_token_id );

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
debug_log("locations %s", locations)

do_cleanup() # async
factory = server.Site(AuthResource(), logFormatter=proxiedLogFormatter)
reactor.listenTCP(args.port, factory, interface=args.address)
reactor.run()
