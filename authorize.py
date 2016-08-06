policies = {'dummy.user':['CreateCluster','RunTask']}

def authorize(request,username):
    actionName = request.headers['X-Amz-Target'].split('.')[1]
    if username not in policies:
        return False
    return actionName in policies[userName]
