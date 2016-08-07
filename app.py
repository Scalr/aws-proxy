from flask import Flask
from flask import request
from flask import make_response
import json
import requests
import authenticate
import authorize

aws_endpoint = "https://ecs.{region}.amazonaws.com/"

app = Flask(__name__)

def build_response_not_authenticated(request):
    response = make_response(json.dumps({'message':'Authentication failure'}))
    response.status_code = 403
    return response

def build_response_not_authorized(request, message):
    response = make_response(json.dumps({'message': message}))
    response.status_code = 403
    return response

def forward_and_resign(request):
    aws_real_endpoint = aws_endpoint.format(region=authorize.get_region_from_request(request))
    new_host = aws_real_endpoint.split('/')[2]
    auth_hdr = authenticate.resign(request, new_host)
    headers = {k:request.headers[k] for k in ['X-Amz-Date', 'X-Amz-Target', 'Content-Type']}
    headers["Authorization"] = auth_hdr
    response = requests.post(aws_real_endpoint, data=request.data, headers=headers)
    print response.text
    final_response = make_response(response.text)
    final_response.status_code = response.status_code
    return final_response

@app.route('/',methods=['POST'])
def handle_query():
    userName = authenticate.authenticate(request)
    if userName is None:
        print 'this request is not authenticated'
        return build_response_not_authenticated(request)
    authorized, error = authorize.authorize(request,userName)
    if not authorized:
        print 'this action is not authorized for %s' % userName
        return build_response_not_authorized(request, error)
    return forward_and_resign(request)

if __name__=='__main__':
    app.run(debug=True)
