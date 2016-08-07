from flask import Flask
from flask import request
from flask import make_response
import requests
import authenticate
import authorize

aws_endpoint = "https://ecs.us-east-1.amazonaws.com/"

app = Flask(__name__)

def build_response_not_authenticated(request):
    response = make_response()
    response.status_code = 400
    return response

def build_response_not_authorized(request):
    response = make_response('You are not allowed to perform this operation')
    response.status_code = 400
    return response

def forward_and_resign(request):
    auth_hdr = authenticate.resign(request)
    headers = {k:request.headers[k] for k in ['X-Amz-Date', 'X-Amz-Target', 'Content-Type']}
    headers["Authorization"] = auth_hdr
    response = requests.post(aws_endpoint, data=request.data, headers=headers)
    print response.text
    return response

@app.route('/',methods=['POST'])
def handle_query():
    userName = authenticate.authenticate(request)
    if userName is None:
        print 'this request is not authenticated'
        return build_response_not_authenticated(request)
    if not authorize.authorize(request,userName):
        print 'this action is not authorized for %s' % userName
        return build_response_not_authorized(request)
    return forward_and_resign(request)

if __name__=='__main__':
    app.run()
