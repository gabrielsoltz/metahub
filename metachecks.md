# MetaChecks

## How to add a new MetaCheck

To add a new MetaCheck for a new ResourceType, start by using this template and create a new file under the metachecks folder with the name of the ResourceType.

```
'''MetaCheck: <AWSResourceType>'''

import boto3


class Metacheck:

    def __init__(self, logger, finding, mh_filters, sess):
        self.logger = logger
        if not sess:
            self.client = boto3.client(<SERVICE>)
        else:
            self.client = sess.client(service_name=<SERVICE>)
        if finding:
            self.mh_filters = mh_filters
            # Populate object with describe functions here
            
    def checks(self):
        checks = [
            ]
        return checks

    def output(self):
        mh_values = {}
        mh_matched = False if self.mh_filters else True

        for check in self.checks():
            hndl = getattr(self, check)()
            mh_values.update({check: hndl})
            if check in self.mh_filters and hndl:
                mh_matched = True
                
        return mh_values, mh_matched
```

Create a function for your test and return True (or data) if the checks match or False if not. 
Add the function name to the variable checks under the function checks().


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