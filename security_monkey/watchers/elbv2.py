from security_monkey.watchers.cloudaux_watcher import CloudAuxWatcher
from cloudaux.aws.elbv2 import describe_load_balancers
from cloudaux.orchestration.aws.elbv2 import get_elbv2


class ELBv2(CloudAuxWatcher):
    index = 'alb'
    i_am_singular = 'ALB'
    i_am_plural = 'ALBs'
    honor_ephemerals = False
    ephemeral_paths = list()

    def list_method(self, **kwargs):
        load_balancers = describe_load_balancers(**kwargs)
        return [load_balancer for load_balancer in load_balancers if not self.check_ignore_list(load_balancer['LoadBalancerName'])]

    def get_method(self, item, **kwargs):
        load_balancer = get_elbv2(item, **kwargs)
        return load_balancer, load_balancer['LoadBalancerName'], None