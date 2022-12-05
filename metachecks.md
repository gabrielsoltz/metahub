# MetaChecks

The ResourceType defines the MetaChecks to be executed. When there is an AWS Security Hub finding for an S3 Bucket (ResourceType: AwsS3Bucket), all the MetaChecks available for that resource will execute and be added as extra information under the ARNs resource.

MetaChecks works this way:

1. Connect to the account where the resource lives
2. Describe the resource
3. Run checks on top of the described resource

## Adding a new AWS ResourceType for MetaChecks

If you want to add MetaChecks for a ResourceType that has not yet been defined in MetaHub, you will first need to add the ResourceType as a Class:

1. Create a new file under `metachecks/checks` with the ResourceType as name, for example `AwsS3Bucket.py`

2. Start with this template as a base. We are using a base Class (MetaChecksBase) to provide the filtering functionality.

```
'''MetaCheck: <AWSResourceType>'''

import boto3
from metachecks.checks.Base import MetaChecksBase

class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):

        self.logger = logger
        if not sess:
            self.client = boto3.client(<<BOTO3 SERVICE>>)
        else:
            self.client = sess.client(service_name=<<BOTO3 SERVICE>>)
        if metachecks:
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks

    def checks(self):
        checks = [

        ]
        return checks
```

3. Define *describe functions* for the ResourceType. These functions will fetch the information you need to then create checks on top of it. For example, if you want to check if an S3 bucket has a public ACL, you first describe the ACLS and then create a function to check if those ACLS are public. This way, you can re-use the describe output for any necessary check. Describe functions in MetaHub are named starting with a `_` as a naming convention. These describe functions will be then be class attributes.

```
def _get_bucket_acl(self):
    try:
        response = self.client.get_bucket_acl(Bucket=self.resource_id)
    except ClientError as err:
        if err.response["Error"]["Code"] in [
            "AccessDenied",
            "UnauthorizedOperation",
        ]:
            self.logger.error(
                "Access denied for get_bucket_acl: " + self.resource_id
            )
            return False
        elif err.response["Error"]["Code"] == "NoSuchBucket":
            # deletion was not fully propogated to S3 backend servers
            # so bucket is still available in listing but actually not exists
            pass
            return False
        else:
            self.logger.error("Failed to get_bucket_acl: " + self.resource_id)
            return False
    return response["Grants"]
```

4. Define an attribute for your describe function, in the previous example, we created a function to describe the ACLs (`_get_bucket_acl`) so we will call this attribute `bucket_acl`

```
'''MetaCheck: <AWSResourceType>'''

import boto3
from metachecks.checks.Base import MetaChecksBase

class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):

        self.logger = logger
        if not sess:
            self.client = boto3.client(<<BOTO3 SERVICE>>)
        else:
            self.client = sess.client(service_name=<<BOTO3 SERVICE>>)
        if metachecks:
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks
            self.bucket_acl = self._get_bucket_acl() --> YOUR DESCRIBE FUNCTION AS AN ATTRIBUTE
```

## Defining MetaChecks

You can code any check you need on top of the data fetched by the *describe functions*.

A MetaCheck should be defined as a yes/no question; when the answer is yes, we can add extra information. When it is no, we can return False or empty data ("", [], {}). For example, if we check if an S3 ACL is public, we can return the permissions that make that ACL public, like READ or FULL_CONTROL. 
When filtering using Meta Checks, we evaluate True as True and True if we return data. So you can output extra information for your resources this way and then integrate it with other tools. As another example, if you are checking a Security Group for unrestrictive open ports, you can output which ports are open and then use that to integrate with Nmap for scanning.

```
def is_bucket_acl_public(self):
    public_acls = []
    if self.bucket_acl:
        for grant in self.bucket_acl:
            if grant["Grantee"]["Type"] == "Group":
                who = grant["Grantee"]["URI"].split("/")[-1]
                if who == "AllUsers" or who == "AuthenticatedUsers":
                    perm = grant["Permission"]
                    public_acls.append(perm)
    if public_acls:
        return public_acls
    return False
```

This function will return the permissions allowed to public (like FULL_CONTROL or READ) or will return False if it's not public.

```
def it_has_bucket_acl_with_cross_account(self):
    acl_with_cross_account = []
    if self.bucket_acl:
        for grant in self.bucket_acl:
            if grant["Grantee"]["Type"] == "CanonicalUser":
                if grant["Grantee"]["ID"] != self.cannonical_user_id:
                    perm = grant["Permission"]
                    acl_with_cross_account.append(perm)
    if acl_with_cross_account:
        return acl_with_cross_account
    return False
```

This function will return the permissions that were granted to other accounts (like FULL_CONTROL or READ) or will return False if it was not granted to other accounts.

To enable the check, add it to the list in the fuction `checks` of your `ResourceType`.


# AwsEc2SecurityGroup

## is_attached_to_network_interfaces

## is_attached_to_ec2_instances

## is_attached_to_managed_services

## is_attached_to_public_ips

## is_public

## is_referenced_by_another_sg


# AwsS3Bucket

## is_bucket_acl_public

## is_bucket_policy_public

## is_public

## it_has_bucket_policy

## it_has_bucket_acl

## it_has_bucket_acl_with_cross_account

## it_has_bucket_policy_allow_with_wildcard_principal

## it_has_bucket_policy_allow_with_wildcard_actions

## it_has_bucket_policy_allow_with_cross_account_principal

## is_encrypted


# AwsElasticsearchDomain

## it_has_access_policies

## it_has_public_endpoint

## it_has_access_policies_public

## is_public