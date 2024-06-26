#! /usr/bin/env python3 --

import sys
if sys.version_info.major < 3: raise SystemExit('error: Python 3 required')

import argparse
import base64
import json
import rsa
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import www_authenticate

parser = argparse.ArgumentParser()
parser.add_argument('-k', '--private-key', required=True, help="RSA private key file")
parser.add_argument('-w', '--webid', required=True)
parser.add_argument('-l', '--id-token-lifetime', type=int, default=3600,
	help="lifetime of id_token (default %(default)s)")
parser.add_argument('-L', '--pop-token-lifetime', type=int, default=120,
	help="lifetime of pop token (default %(default)s)")
parser.add_argument('-a', '--app-id', default="https://app.example/oauth/code",
	help="application id (default %(default)s)")
parser.add_argument('-i', '--issuer', default="https://self-issued.me",
	help="id_token issuer (default %(default)s)")
parser.add_argument('-K', '--key-id', help="JWK kid (default %(default)s)")
parser.add_argument('-A', '--app-auth', help="app authorizations URI (use multiple times)", action='append')
parser.add_argument('-t', '--token-only', action='store_true',
	help="output the bare access token instead of the full JSON response")
parser.add_argument('-d', '--debug', action='store_true')
parser.add_argument('uri', help="URI to access")

args = parser.parse_args()

is_self_issued = args.issuer == "https://self-issued.me"

privateKey = rsa.PrivateKey.load_pkcs1(open(args.private_key, "rb").read())

def as_bytes(s):
	return bytes(s, 'utf-8') if str == type(s) else s

def as_str(s):
	return str(s, 'utf-8') if bytes == type(s) else s

def b64u_encode(s):
	return str(base64.urlsafe_b64encode(as_bytes(s)), 'utf-8').rstrip('=')

def compact_json(obj):
	return json.dumps(obj, indent=None, separators=(',', ':'))

def urlencode(query):
	# urllib.urlencode will encode a None value as a string None.
	# this will suppress None and empty values.
	rv = []
	for k, v in query.items():
		if v:
			rv.append('%s=%s' % (urllib.parse.quote_plus(str(k)), urllib.parse.quote(str(v), '')))
	return '&'.join(rv)

def make_jwt(obj, key_id=None):
	header = {"alg":"RS256","typ":"JWT"}
	if key_id:
		header['kid'] = args.key_id
	header = compact_json(header)
	payload = compact_json(obj)
	data = b64u_encode(header) + "." + b64u_encode(payload)
	signature = rsa.sign(as_bytes(data), privateKey, "SHA-256")
	return data + "." + b64u_encode(signature)

def make_jwk():
	rv = dict(
		kty="RSA",
		n=b64u_encode(rsa.transform.int2bytes(privateKey.n)),
		e=b64u_encode(rsa.transform.int2bytes(privateKey.e)),
		alg="RS256",
		key_ops=["verify"]
	)
	if(args.key_id):
		rv['kid'] = args.key_id
	return rv

def make_id_token(webid, client_id, nonce, lifetime, redirect_uri=None, cnf=None, sub_jwk=None):
	now = time.time()
	aud = [ client_id ]
	if redirect_uri:
		aud.append(redirect_uri)
	token = {
		"webid": webid,
		"iss": args.issuer,
		"sub": webid,
		"aud": aud,
		"exp": int(now + lifetime),
		"iat": int(now),
		"auth_time": int(now),
		"acr": "0",
		"azp": client_id,
		"jti": str(uuid.uuid4()),
		"nonce": nonce
	}
	if cnf:
		token['cnf'] = cnf
	if sub_jwk:
		token['sub_jwk'] = sub_jwk
	return make_jwt(token, args.key_id)

def make_proof_token(id_token, aud, nonce, issuer, lifetime):
	now = time.time()
	token = {
		"aud": aud,
		"nonce": nonce,
		"sub": id_token,
		"iss": issuer,
		"iat": int(now),
		"exp": int(now + lifetime),
		"jti": str(uuid.uuid4())
	}
	if args.app_auth:
		token['app_authorizations'] = args.app_auth[0] if len(args.app_auth) == 1 else args.app_auth
	return make_jwt(token)

uri = urllib.parse.urldefrag(args.uri)[0]

def open_url(url, data=None, headers={}):
	if data:
		if isinstance(data, dict):
			data = urlencode(data)
	request = urllib.request.Request(url, data=as_bytes(data), headers=headers)
	try:
		return urllib.request.urlopen(request)
	except urllib.error.HTTPError as e:
		return e

response = open_url(uri, headers=dict(authorization='bearer bad-token'))
if response.getcode() != 401:
	print("oops, expected 401")
	raise SystemExit(-1)

www_auth = www_authenticate.parse(response.headers['WWW-Authenticate'])['Bearer']
if not all([x in www_auth for x in ['nonce', 'scope', 'token_pop_endpoint']]) or \
		not all([x in www_auth['scope'].split() for x in ['openid', 'webid']]):
	print("oops, WWW-Authenticate isn't for webid-auth-protocol", response.headers['WWW-Authenticate'])
	raise SystemExit(-1)

jwk = make_jwk()

id_token = make_id_token(args.webid, "cli-tool", nonce=str(uuid.uuid4()), lifetime=args.id_token_lifetime,
		redirect_uri=args.app_id, cnf=dict(jwk=jwk), sub_jwk=jwk if is_self_issued else None)

proof_token = make_proof_token(id_token=id_token, aud=uri, nonce=www_auth['nonce'], issuer=args.app_id, lifetime=args.pop_token_lifetime)
if args.debug:
	print("proof token", proof_token)

pop_endpoint = urllib.parse.urljoin(uri, www_auth['token_pop_endpoint'])

response = open_url(pop_endpoint, data=dict(proof_token=proof_token))
if 200 != response.getcode():
	print("oops, got", response.getcode())
	print("response\n", response.read())
	raise SystemExit(-1)

result = json.loads(response.read())

if args.token_only:
	print(result.get('access_token'))
else:
	print(json.dumps(result, indent=4))
