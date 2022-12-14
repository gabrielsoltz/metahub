# MetaChecks

The ResourceType defines the MetaChecks to be executed. When there is an AWS Security Hub finding for an S3 Bucket (ResourceType: AwsS3Bucket), all the MetaChecks available for that resource will execute and be added as extra information under the ARNs resource.

- [How it works](#how-it-works)
- [Adding a new AWS ResourceType for MetaChecks](#adding-a-new-aws-resourcetype-for-metachecks)
- [Creating MetaChecks](#creating-metachecks)
- [AwsEc2SecurityGroup](#awsec2securitygroup)
- [AwsS3Bucket](#AwsS3Bucket)
- [AwsElasticsearchDomain](#AwsElasticsearchDomain)
- [AwsEc2Instance](#AwsEc2Instance)

## How it works

MetaChecks works this way:

1. Connect to the account where the resource lives assuming the provided role (`--mh-assume-role`)
2. Describe the resource using describe functions
3. Executes MetaChecks on top of the described resource
4. Add the MetaChecks output to your affected resources
5. Apply filters if provided (`--mh-filters-checks`)
6. Output the list of affected resources with MetaChecks outputs that matchs your filters

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
        if metachecks:
            region = finding["Region"]
            if not sess:
                self.client = boto3.client(<<BOTO3 SERVICE>>, region_name=region)
            else:
                self.client = sess.client(service_name=<<BOTO3 SERVICE>>, region_name=region)
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
        self.logger.error("Failed to get_bucket_acl {}, {}".format(self.resource_id, err))
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
        if metachecks:
            region = finding["Region"]
            if not sess:
                self.client = boto3.client(<<BOTO3 SERVICE>>, region_name=region)
            else:
                self.client = sess.client(service_name=<<BOTO3 SERVICE>>, region_name=region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks

            self.bucket_acl = self._get_bucket_acl() --> YOUR DESCRIBE FUNCTION AS AN ATTRIBUTE
```

5. Import Metacheck in metachecks/checks/__init__.py file

## Creating MetaChecks

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

```
    def checks(self):
        checks = [
            "it_has_bucket_acl_with_cross_account",
            "is_bucket_acl_public"
        ]
        return checks
```

# MetaChecks Nomenclature

MetaChecks are defined in the form of:

is_
its_associated_to_
it_has_
its_referenced_by_

## is_

Refers to the affected resource itself.

### Public

Public refers to Network Layer. Must be effectively Public, meaning that if a resource, has a Public IP but the Security Group is closed, the resource is not Public. 

is_public

### Unrestricted

Unrestricted refers to Policies Layer (API, IAM, Resources Policies, Rules, etc.). 

is_unrestricted

### Encryption

is_encrypted
is_rest_encrypted
is_transit_encrypted

### Default

is_default

### Status

is_running

## its_associated_to

> Resources that are indepedently managed (For example and EC2 Elastic IP)

When True returns list of something_is_associated_to...

its_associated_to_<something_is_associated_to>
its_associated_to_<something_is_associated_to>_unencrypted
its_associated_to_<something_is_associated_to>_unrestricted_cross_account
its_associated_to_<something_is_associated_to>_unrestricted_wildcard
its_associated_to_<something_is_associated_to>_unencrypted
its_associated_to_<something_is_associated_to>_public

## it_has

> Resources that only exist as part of the affected resources (For example an Instance EC2 IP)

When True returns list of something_it_has...

it_has_<something_it_has>
it_has_<something_it_has>_unencrypted
it_has_<something_it_has>_unrestricted_cross_account
it_has_<something_it_has>_unrestricted_wildcard
it_has_<something_it_has>_unencrypted
it_has_<something_it_has>_public

## its_referenced_by

> Resources that are not part but are referencing the affected resource (For example a Security Group referencing the affected Security Group as source/destination)

When True returns list of something_that_is_referencing_the_affected_resource...

its_referenced_by_<something_that_is_referencing_the_affected_resource>