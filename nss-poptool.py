#! /usr/bin/env python --

import argparse
import base64
import hashlib
import json
import rsa
import sys
import time
import urllib
import urllib2
import urlparse
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('-k', '--private-key', required=True, help="RSA private key file")
parser.add_argument('-w', '--webid', required=True)
parser.add_argument('-i', '--issuer', required=True,
	help="id_token issuer (default %(default)s)")
parser.add_argument('-K', '--key-id', help="JWK kid, required by NSS, must match JWKS", required=True)
parser.add_argument('-l', '--id-token-lifetime', type=int, default=3600,
	help="lifetime of id_token (default %(default)s)")
parser.add_argument('-L', '--pop-token-lifetime', type=int, default=120,
	help="lifetime of pop token (default %(default)s)")
parser.add_argument('-a', '--app-id', default="https://app.example/oauth/code",
	help="application id (default %(default)s)")
parser.add_argument('-d', '--debug', action='store_true')
parser.add_argument('-j', '--jwks', help="print jwks file instead of POPToken", action='store_true')
parser.add_argument('uri', help="URI to access")

args = parser.parse_args()

is_self_issued = args.issuer == "https://self-issued.me"

privateKey = rsa.PrivateKey.load_pkcs1(open(args.private_key, "rb").read())

def b64u_encode(s):
	return base64.urlsafe_b64encode(s).rstrip('=')

def compact_json(obj):
	return json.dumps(obj, indent=None, separators=(',', ':'))

def urlencode(query):
	# urllib.urlencode will encode a None value as a string None.
	# this will suppress None and empty values.
	rv = []
	for k, v in query.iteritems():
		if v:
			rv.append('%s=%s' % (urllib.quote_plus(str(k)), urllib.quote(str(v), '')))
	return '&'.join(rv)

def make_jwt(obj, key_id=None):
	header = {"alg":"RS256","typ":"JWT"}
	if key_id:
		header['kid'] = args.key_id
	header = compact_json(header)
	payload = compact_json(obj)
	data = b64u_encode(header) + "." + b64u_encode(payload)
	signature = rsa.sign(data, privateKey, "SHA-256")
	return data + "." + b64u_encode(signature)

def make_jwk(key_id):
	rv = dict(
		kty="RSA",
		n=b64u_encode(rsa.transform.int2bytes(privateKey.n)),
		e=b64u_encode(rsa.transform.int2bytes(privateKey.e)),
		alg="RS256",
		key_ops=["verify"]
	)
	if(key_id):
		rv['kid'] = key_id
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
		"exp": long(now + lifetime),
		"iat": long(now),
		"auth_time": long(now),
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
		"id_token": id_token,
		"iss": issuer,
		"iat": long(now),
		"exp": long(now + lifetime),
		"jti": str(uuid.uuid4()),
		"token_type": "pop"
	}
	return make_jwt(token)

jwk = make_jwk(args.key_id)

if args.jwks:
	print json.dumps(dict(keys=[jwk]), indent=4)
	raise SystemExit(0)

parts = urlparse.urlparse(args.uri)
origin = parts.scheme + '://' + parts.netloc

id_token = make_id_token(args.webid, "cli-tool", nonce=str(uuid.uuid4()), lifetime=args.id_token_lifetime,
		redirect_uri=args.app_id, cnf=dict(jwk=jwk), sub_jwk=jwk if is_self_issued else None)

proof_token = make_proof_token(id_token=id_token, aud=origin, nonce=str(uuid.uuid4()), issuer=args.app_id, lifetime=args.pop_token_lifetime)

print proof_token
