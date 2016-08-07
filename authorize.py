import sys
import authenticate

db_groups = {
    'dummy.user': [ 'group2']
}
db_policy_types = {
                    'location':
                    {
                        'target_actions': ['CreateCluster'],
                        'failure_message': 'You do not have access to this region.'
                    },
                    'forbid_privileged':
                    {
                        'target_actions': ['RegisterTaskDefinition'],
                        'failure_message': 'You are not allowed to register a task definition with a privileged container'
                    },
                    'image_source':
                    {
                        'target_actions': ['RegisterTaskDefinition'],
                        'failure_message': 'You are not allowed to pull images from this repository.'
                    }
                  }

db_policies = [
            {
                'type': 'location',
                'target_group': 'group1',
                'args':
                {
                    'allowed_locations': ['us-east-1']
                }
            },
            {
                'type': 'location',
                'target_group': 'group2',
                'args':
                {
                    'allowed_locations': ['us-west-1']
                }
            },
            {
                'type': 'forbid_privileged',
                'target_group': 'group1',
                'args':{}
            }
        ]

def policy_forbid_privileged(request,args):
    if 'containerDefinitions' not in request.get_json(force=True):
        return True
    definitions = request.get_json(force=True)['containerDefinitions']
    for cont in definitions:
        if 'privileged' in cont and cont['privileged']:
            return False
    return True

def get_region_from_request(request):
    authstring = request.headers['Authorization']
    cred = authenticate.extract_from_auth(authstring,'Credential')
    return cred.split('/')[2]

def policy_location(request,args):
    allowed_locations = args['allowed_locations']
    return get_region_from_request(request) in allowed_locations

def policy_image_source(request, args):
    allowed_sources = args['sources']
    if '*' in allowed_sources:
        return True
    containerDefs = request.get_json(force=True)['containerDefinitions']
    for c in containerDefs:
        image = c['image']
        if image.find('/') == -1:
            return False
        source = image[:image.find('/')]
        if not source in allowed_sources:
            return False
    return True

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
    error_message = ''
    for ptype in policies_to_apply:
        res2 = False
        for p in policies_to_apply[ptype]:
            res2 = res2 or getattr(sys.modules[__name__],'policy_'+ptype)(request,p['args'])
        if not res2:
            print 'Request blocked by policy: ', ptype
            error_message = db_policy_types[ptype]['failure_message']
            res = False
            break

    return res, error_message
