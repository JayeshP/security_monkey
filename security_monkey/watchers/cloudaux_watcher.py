from security_monkey.watcher import Watcher, ChangeItem
from security_monkey.decorators import record_exception, iter_account_region


class CloudAuxWatcher(Watcher):
    index = 'abstract'
    i_am_singular = 'Abstract Watcher'
    i_am_plural = 'Abstract Watchers'
    honor_ephemerals = False
    ephemeral_paths = list()
    def list_method(self, **kwargs): raise Exception('Not Implemented')
    def get_method(self, item, **kwargs): raise Exception('Not Implemented')

    def __init__(self, accounts=None, debug=None):
        super(CloudAuxWatcher, self).__init__(accounts=accounts, debug=debug)
   
    @record_exception(source='{index}-watcher'.format(index=index), pop_exception_fields=True) 
    def invoke_list_method(self, **kwargs):
        return self.list_method(**kwargs)

    @record_exception(source='{index}-watcher'.format(index=index), pop_exception_fields=True) 
    def invoke_get_method(self, item, **kwargs):
        return self.get_method(item, **kwargs)

    def slurp(self):
        self.prep_for_slurp()

        @iter_account_region(index=self.index, accounts=self.accounts)
        def slurp_items(**kwargs):
            results = []
            item_list = self.invoke_list_method(**kwargs)
            if not item_list:
                return results, kwargs.get('exception_map', {})

            for item in item_list:
                item, item_name, override_region = self.invoke_get_method(item, **kwargs)
                if item:
                    item = CloudAuxChangeItem.from_item(item_name, item, override_region, **kwargs)
                    results.append(item)

            return results, kwargs.get('exception_map', {})
        return slurp_items()

class CloudAuxChangeItem(ChangeItem):
    def __init__(self, index=None, account=None, region='us-east-1', name=None, arn=None, config={}):
        super(CloudAuxChangeItem, self).__init__(
            index=index,
            region=region,
            account=account,
            name=name,
            arn=arn,
            new_config=config)

    @classmethod
    def from_item(cls, name, item, override_region, **kwargs):
        return cls(
            name=name,
            arn=item['Arn'],
            account=kwargs['account_name'],
            index=kwargs['index'],
            region=override_region or kwargs['region'],
            config=item)