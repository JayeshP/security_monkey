from security_monkey.watchers.cloudaux_watcher import CloudAuxWatcher
from security_monkey.exceptions import SecurityMonkeyException
from cloudaux.aws.s3 import list_buckets
from cloudaux.orchestration.aws.s3 import get_bucket


class S3(CloudAuxWatcher):
    index = 's3'
    i_am_singular = 'S3 Bucket'
    i_am_plural = 'S3 Buckets'
    honor_ephemerals = True
    ephemeral_paths = ['GrantReferences']
    
    def list_method(self, **kwargs):
        buckets = list_buckets(**kwargs)['Buckets']
        return [bucket['Name'] for bucket in buckets if not self.check_ignore_list(bucket['Name'])]

    def get_method(self, item, **kwargs):
        bucket = get_bucket(item, **kwargs)
        
        if bucket and bucket.get("Error"):
            raise SecurityMonkeyException("S3 Bucket: {} fetching error: {}".format(item, bucket["Error"]))
        
        return bucket
