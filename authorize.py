import sys
import authenticate
db_groups = {'dummy.user':['group1','group2']}
db_policy_types = {
                'location':
                    {
                    'target_actions':['CreateCluster']
                    }
                }

db_policies = [{
                'type':'location',
                'target_group':'group1',
                'args':
                    {
                    'allowed_locations':['us-east-1']
                    }
            },
            {
                'type':'location',
                'target_group':'group2',
                'args':
                    {
                    'allowed_locations':['us-west-1']
                    }
            }
            ]

def get_region_from_request(request):
    authstring = request.headers['Authorization']
    cred = authenticate.extract_from_auth(authstring,'Credential')
    return cred.split('/')[2]

def policy_location(request,args):
    allowed_locations = args['allowed_locations']
    return get_region_from_request(request) in allowed_locations

def authorize(request,username):
    actionName = request.headers['X-Amz-Target'].split('.')[1]
    if username not in db_groups:
        return False
    groups = db_groups[username]
    policies_to_apply = {}
    for p in db_policies:
        if p['target_group'] in groups:
            if not p['type'] in policies_to_apply:
                policies_to_apply[p['type']] = [p]
            else:
                policies_to_apply[p['type']].append(p)
    res = True
    for ptype in policies_to_apply:
        res2 = False
        for p in policies_to_apply[ptype]:
            res2 = res2 or getattr(sys.modules[__name__],'policy_'+ptype)(request,p['args'])
        if not res2:
            print 'Request blocked by policy: ',ptype
            res = False
            break

    return res
