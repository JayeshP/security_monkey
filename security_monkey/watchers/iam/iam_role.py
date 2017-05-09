from security_monkey.watchers.cloudaux_watcher import CloudAuxWatcher
from security_monkey.watchers.cloudaux_watcher import CloudAuxChangeItem
from cloudaux.aws.iam import list_roles
from cloudaux.orchestration.aws.iam.role import get_role
from security_monkey.decorators import iter_account_region


class IAMRole(CloudAuxWatcher):
    index = 'iamrole'
    i_am_singular = 'IAM Role'
    i_am_plural = 'IAM Roles'
    honor_ephemerals = False
    ephemeral_paths = list()

    def __init__(self, **kwargs):
        super(IAMRole, self).__init__(**kwargs)
        self.batched_size = 100
        self.done_slurping = False
        self.next_role = 0

    def slurp_list(self):
        self.prep_for_batch_slurp()

        @iter_account_region(index=self.index, accounts=self.accounts)
        def get_role_list(**kwargs):
            roles = self.invoke_list_method(**kwargs)

            if not roles:
                self.done_slurping = True
                roles = list()

            return roles, kwargs['exception_map']

        roles, exception_map = get_role_list()
        self.total_list.extend(roles)

        return exception_map

    def slurp(self):
        batched_items = list()

        @iter_account_region(index=self.index, accounts=self.accounts)
        def slurp_items(**kwargs):
            item_list = list()
            role_counter = self.batch_counter * self.batched_size
            while self.batched_size - len(item_list) > 0 and not self.done_slurping:
                cursor = self.total_list[role_counter]
                item_details = self.invoke_get_method(cursor, name=cursor['RoleName'], **kwargs)
                if item_details:
                    item = CloudAuxChangeItem.from_item(
                        name=item_details[1],
                        item=item_details[0],
                        override_region=item_details[2], **kwargs)
                    item_list.append(item)
                role_counter += 1
                if role_counter == len(self.total_list):
                    self.done_slurping = True
            self.batch_counter += 1
            return item_list, kwargs['exception_map']

        retval = slurp_items()
        print('RETVAL {}'.format(retval))
        return retval


    def list_method(self, **kwargs):
        roles = list_roles(**kwargs)
        return [role for role in roles if not self.check_ignore_list(role['RoleName'])]

    def get_method(self, item, **kwargs):
        role = get_role(dict(item), **kwargs)
        return role, role['RoleName'], 'universal'
