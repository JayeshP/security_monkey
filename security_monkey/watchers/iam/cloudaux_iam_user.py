from security_monkey.watchers.cloudaux_watcher import CloudAuxWatcher
from cloudaux.aws.iam import list_users
from cloudaux.orchestration.aws.iam.user import get_user


class IAMUser(CloudAuxWatcher):
    index = 'iamuser'
    i_am_singular = 'IAM User'
    i_am_plural = 'IAM Users'
    honor_ephemerals = True
    ephemeral_paths = [
        "PasswordLastUsed",
            "AccessKeys$*$LastUsedDate",
            "AccessKeys$*$Region",
            "AccessKeys$*$ServiceName"
        ]
    
    def list_method(self, **kwargs):
        users = list_users(**kwargs)
        return [user for user in users if not self.check_ignore_list(user['UserName'])]
    
    def get_method(self, item, **kwargs):
        user = get_user(item, **kwargs)
        return user, user['UserName']