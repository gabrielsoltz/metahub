# Context Module

The context module has 4 main components: config, tags, account and cloudtrail.

The config component is responsible for fetching the configuration and the associated resources. This configuration and associated resources are defined by resource type, under `lib/context/resources` you will find a file for each resource type.

## Adding a new AWS ResourceType

If you want to add context for a ResourceType that has not yet been defined in MetaHub, you will first need to add the ResourceType as a Class:

1. Create a new file under `lib/context/resources` with the ResourceType as name, for example `AwsS3Bucket.py`

2. Start with this template as a base. We are using a base Class MetaChecksBase for every ResourceType.

```python
"""ResourceType: Name of the ResourceType"""

from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import ContextBase


class Metacheck(ContextBase):
    def __init__(
        self,
        logger,
        finding,
        mh_filters_config,
        sess,
        drilled=False,
    ):
        self.logger = logger
        self.sess = sess
        self.mh_filters_config = mh_filters_config
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(self.logger, "SERVICE", self.region, self.sess) --> YOUR BOTO3 CLIENT
        # Describe Resource
        self.RESOURCE_TYPE = self.describe_RESOURCE_TYPE()       --> You will need a describe function for your resource type
        if not self.RESOURCE_TYPE:                               --> Handling if the resource does not exist
            return False
        # Drilled Associations
        self.iam_roles = self._describe_instance_iam_roles()     --> Add your associations, needs to be a dictionary {"arn": {}}

    # Parse                                                      --> How to parse the resource id from the ARN
    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_id = (                                     --> When the resource is drilled, it get's the arn as drilled
            finding["Resources"][0]["Id"].split("/")[-1]
            if not drilled
            else drilled.split("/")[-1]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled --> When the resource is drilled, it get's the arn as drilled

    # Describe Functions

    def describe_RESOURCE_TYPE(self):                                             --> Describe function for your resource type
        try:
            response = self.client.describe_instances(
                InstanceIds=[
                    self.resource_id,
                ],
                Filters=[
                    {
                        "Name": "instance-state-name",
                        "Values": [
                            "pending",
                            "running",
                            "shutting-down",
                            "stopping",
                            "stopped",
                        ],
                    }
                ],
            )
            if response["Reservations"]:
                return response["Reservations"][0]["Instances"][0]
        except ClientError as err:
            if not err.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                self.logger.error(
                    "Failed to describe_instance: {}, {}".format(self.resource_id, err)
                )
        return False

    # Context Config


    def associations(self):
        associations = {}                                                                    --> The associations
        return associations

    def checks(self):
        checks = {}                                                                           --> The config checks
        return checks

```

3. Define as many describe functions for the ResourceType you need. These functions will fetch the information you need to then create config checks on top of it.

```python
def get_bucket_acl(self):
    try:
        response = self.client.get_bucket_acl(Bucket=self.resource_id)
    except ClientError as err:
        self.logger.error("Failed to get_bucket_acl {}, {}".format(self.resource_id, err))
        return False
    return response["Grants"]
```

4. Define config check functions to add keys to the config key, and add those functions to the checks function.

```python
def public_dns(self):
    public_dns = False
    if self.instance:
        public_dns = self.instance.get("PublicDnsName")
    return public_dns

def checks(self):
    checks = {
        "public_dns": self.public_dns(),
    }
    return checks
```

5. Add the associated resources to the associations function.

```python
def associations(self):
    associations = {
        "iam_roles": self.iam_roles,
    }
    return associations
```

4. Import Metacheck in lib/resources/**init**.py file
