from security_monkey.watchers.cloudaux_watcher import CloudAuxWatcher
from cloudaux.aws.elb import describe_load_balancers
from cloudaux.orchestration.aws.elb import get_load_balancer


class ELB(CloudAuxWatcher):
    index = 'elb'
    i_am_singular = 'ELB'
    i_am_plural = 'ELBs'
    honor_ephemerals = False
    ephemeral_paths = list()

    def list_method(self, **kwargs):
        load_balancers = describe_load_balancers(**kwargs)
        return [load_balancer for load_balancer in load_balancers if not self.check_ignore_list(load_balancer['LoadBalancerName'])]

    def get_method(self, item, **kwargs):
        load_balancer = get_load_balancer(item, **kwargs)
        return load_balancer, load_balancer['LoadBalancerName'], None