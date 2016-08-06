# -*- coding: utf-8 -*-
import sys, os, base64, datetime, hashlib, hmac 
import requests

users = {
    'dummy.user': 'crapineedasigningkey'
}

def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

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
    return header[begin:header.find(',', begin)]

def authenticate(request):
    host = request.headers['Host']
    auth = request.headers['Authorization'].split(' ')
    print 'Auth:', auth
    sig_version = auth[0]
    if sig_version != 'AWS4-HMAC-SHA256':
        return 'Error: unsupported signing scheme'
    cred = extract_from_auth(auth, 'Credential')
    signed_headers = extract_from_auth(auth, 'SignedHeaders')
    return None


