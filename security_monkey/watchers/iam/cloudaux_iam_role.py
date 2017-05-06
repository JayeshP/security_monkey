from security_monkey.watchers.cloudaux_watcher import CloudAuxWatcher
from cloudaux.aws.iam import list_roles
from cloudaux.orchestration.aws.iam.role import get_role


class IAMRole(CloudAuxWatcher):
    index = 'iamrole'
    i_am_singular = 'IAM Role'
    i_am_plural = 'IAM Roles'
    honor_ephemerals = False
    ephemeral_paths = list()
    
    def list_method(self, **kwargs):
        roles = list_roles(**kwargs)
        return [role for role in roles if not self.check_ignore_list(role['RoleName'])]
        
    def get_method(self, item, **kwargs):
        role = get_role(dict(item), **kwargs)
        return role, role['RoleName'], 'universal'
        