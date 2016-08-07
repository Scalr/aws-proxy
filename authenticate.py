# -*- coding: utf-8 -*-
import sys, os, base64, datetime, hashlib, hmac
import requests

users = {
    'dummy.user': 'crapineedasigningkey'
}

def sign(key, msg):
    return hmac.new(key,msg.encode('utf-8'),hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

def extract_from_auth(header, desc):
    begin = header.find(desc)
    if begin == -1:
        raise LookupError
    begin += len(desc) + 1
    end = header.find(',', begin)
    if end == -1:
        return header[begin:]
    else:
        return header[begin:end]

def authenticate(request):
    auth = request.headers['Authorization']
    amzdate = request.headers['X-Amz-Date']
    algorithm = auth.split(' ')[0]
    if algorithm != 'AWS4-HMAC-SHA256':
        raise Exception("Unsupported signature algorithm")
    cred = extract_from_auth(auth, 'Credential')
    key_id, credential_scope = cred.split('/', 1)
    datestamp, region, service, _ = credential_scope.split('/')
    if not key_id in users:
        return None

    method = request.method
    amz_target = request.headers['X-Amz-Target']
    request_parameters = request.data
    secret_key = users[key_id]
    signed_headers = extract_from_auth(auth, 'SignedHeaders')
    given_sig = extract_from_auth(auth, 'Signature')

    canonical_uri = request.path
    canonical_querystring = request.query_string
    canonical_headers = '\n'.join(k.lower() + ':' + v for k, v in sorted(request.headers.items()) if k.lower() in signed_headers.split(';')) + '\n'

    payload_hash = hashlib.sha256(request_parameters).hexdigest()
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
    string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()
    signing_key = getSignatureKey(secret_key, datestamp, region, service)
    computed_sig = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
    if computed_sig != given_sig:
        return None
    return key_id 

def resign(request, newhost):
    auth = request.headers['Authorization']
    amzdate = request.headers['X-Amz-Date']
    algorithm = auth.split(' ')[0]
    cred = extract_from_auth(auth, 'Credential')
    key_id, credential_scope = cred.split('/', 1)
    datestamp, region, service, _ = credential_scope.split('/')

    method = request.method
    amz_target = request.headers['X-Amz-Target']
    request_parameters = request.data
    secret_key = os.environ.get('SCALR_SECRET')
    key_id = os.environ.get('SCALR_KEYID')

    signed_headers = extract_from_auth(auth, 'SignedHeaders')

    canonical_uri = request.path
    canonical_querystring = request.query_string
    headers_to_sign = {k.lower(): v for k, v in request.headers.items() if k.lower() in signed_headers.split(';')}
    headers_to_sign['host'] = newhost
    canonical_headers = '\n'.join(k + ':' + v for k, v in sorted(headers_to_sign.items())) + '\n'

    payload_hash = hashlib.sha256(request_parameters).hexdigest()
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
    print 'Canonical Request: ',canonical_request
    string_to_sign = algorithm + '\n' +  amzdate + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request).hexdigest()
    print 'String to sign:', string_to_sign
    signing_key = getSignatureKey(secret_key, datestamp, region, service)
    computed_sig = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
    authorization_header = algorithm + ' ' + 'Credential=' + key_id + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + computed_sig
    return authorization_header
