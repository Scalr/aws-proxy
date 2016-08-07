from flask import Flask
import authenticate
import authorize
app = Flask(__name__)

def build_response_not_authenticate(request):
    response = Flask.make_response()
    response.status_code = 400
    return response

def forward_and_resign(request):
    pass

@app.route('/',methods=['POST'])
def handle_query():
    userName = authenticate.authenticate(request)
    if userName is None:
        print 'this request is not authenticated'
        return build_response_not_authorized(request)
    if not authorize.authorize(request,userName):
        print 'this action is not authorized for %s' % username
        return build_response_not_authorized(request)
    return forward_and_resign(request)

if __name__=='__main__':
    app.run()
