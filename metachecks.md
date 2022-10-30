# MetaChecks

## How to add a new ResourceType

To add a new ResourceType, start by using this template and create a new file under the metachecks folder with the name of the ResourceType.

```
'''MetaCheck: <AWSResourceType>'''

import boto3
from metachecks.checks.Base import MetaChecksBase


class Metacheck(MetaChecksBase):

    def __init__(self, logger, finding, metachecks, mh_filters_checks, metatags, mh_filters_tags, sess):
        self.logger = logger
        if not sess:
            self.client = boto3.client("ec2")
        else:
            self.client = sess.client(service_name="ec2")
        if metatags or metachecks:
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            if metatags:
                self.mh_filters_tags = mh_filters_tags
                self.tags = self._tags()
            if metachecks:
                self.mh_filters_checks = mh_filters_checks
                # Populate object with describe functions here
            
    def checks(self):
        checks = [
            ]
        return checks
```

Create a function for your test and return True (or data) if the checks match or False if not. 
Add the function name to the variable checks under the function checks().


## How to add a new MetaCheck




## Checks

# AwsEc2SecurityGroup

## is_attached_to_network_interfaces

## is_attached_to_ec2_instances

## is_attached_to_managed_services

## is_attached_to_public_ips

## is_public

# AwsS3Bucket

## is_bucket_acl_public

## is_bucket_policy_public

## is_public