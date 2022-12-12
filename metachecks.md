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

# AwsEc2SecurityGroup

## is_attached_to_network_interfaces

Check if the Security Group is attached to Network Interfaces (ENIs). 
Return:
    - List of attached `NetworkInterfaceId` (True)
    - False

## is_attached_to_ec2_instances

Check if the Security Group is attached to EC2 Instances. 
Return:
    - List of attached `InstanceId` (True)
    - False

## is_attached_to_managed_services

Check if the Security Group is attached to AWS Managed Services (like ELB, ALB, EFS, etc.). 
Return:
    - List of attached `Descriptions` (True)
    - False

## is_attached_to_public_ips

Check if the Security Group is attached to Network Interfaces (ENIs) with Public IPs. 
Return:
    - List of attached `Public Ips` (True)
    - False

## is_public

Check if the Security Group is Public based on if `is_attached_to_public_ips`
Return
    - True
    - False

## is_referenced_by_another_sg

Check if the security group is referenced by another Security Group
Return
    - List of SG `GroupId` (True)
    - False

# AwsS3Bucket

## is_bucket_acl_public

Check if there is a bucket acl and if it contains at least one public statement (`AllUsers` or `AuthenticatedUsers`)
Return
    - List of permissions granted for the public statement (True)
    - False

## is_bucket_policy_public

Check if there is a bucket policy and if it contains at least one public statement (Principal = `*` with no condition)
Return
    - List of statements granted for public (True)
    - False

## is_public

Check if either `is_bucket_acl_public` or `is_bucket_policy_public` is True. 
Return
    - True
    - False

## it_has_bucket_policy

Check if the bucket has a bucket policy
Return
    - The bucket policy (True)
    - False

## it_has_bucket_acl

Check if the bucket has a bucket acl
Return
    - The bucket acl
    - False

## it_has_bucket_acl_with_cross_account

Check if the bucket has a bucket acl and if it was granted to another AWS Account based on CanonicalUser 
Return
    - List of permissions granted for that CanonicalUser (True)
    - False

## it_has_bucket_policy_allow_with_wildcard_principal

Check if the bucket has a bucket policy and if it contains an allow statment with wildcard (*) as principal
Return
    - List of statements granted for wildcard principal (True)
    - False

## it_has_bucket_policy_allow_with_wildcard_actions

Check if the bucket has a bucket policy and if it contains an allow statment with wildcard (*) as actions
Return
    - List of statements granted with wildcard actions (True)
    - False


## it_has_bucket_policy_allow_with_cross_account_principal

Check if the bucket has a bucket policy and if it contains an allow statement granted to another account based on Principal
Return
    - List of external principals (True)
    - False

## is_encrypted

Check if the bucket is encrypted
Return
    - True
    - False

# AwsElasticsearchDomain

## it_has_access_policies

Check if the Elastic Search Domain has an access policy
Return
    - The list of access policies (True)
    - False

## it_has_public_endpoint

Check if the Elastic Search Domain has a public endpoint
Return
    - The public endpoint (True)
    - False

## it_has_access_policies_public

Check if the Elastic Search Domain has an access policy and if any of their statements are public (Principal = `*` with no condition)
Return
    - The public statements (True)
    - False

## is_public

Check if the Elastic Search Domain is public by checking `it_has_access_policies_public` and `it_has_public_endpoint`
Return
    - True
    - False

## is_rest_encrypted

Check if the Elastic Search Domain is configured with `EncryptionAtRestOptions`
Return
    - True
    - False

## is_node_to_node_encrypted
Check if the Elastic Search Domain is configured with `NodeToNodeEncryptionOptions`
Return
    - True
    - False

## is_encrypted

Check if the Elastic Search Domain is public by checking `is_rest_encrypted` and `is_node_to_node_encrypted`
Return
    - True
    - False


# AwsEc2Instance

## it_has_public_ip

Check if the EC2 Instance has a Public Ip
Return
    - The public IP (True)
    - False

## it_has_private_ip

Check if the EC2 Instance has a Private Ip
Return
    - The private IP (True)
    - False

## it_has_key

Check if the EC2 Instance has key pair
Return
    - The name of the key pair (True)
    - False

## it_has_private_dns

Check if the EC2 Instance has a Private DNS
Return
    - The private DNS (True)
    - False

## it_has_public_dns

Check if the EC2 Instance has a Public DNS
Return
    - The public DNS (True)
    - False

## is_running

Check if the EC2 Instance is in "running" state
Return
    - True
    - False

## is_attached_to_security_groups

Check if the EC2 Instance is attached to Security Groups
Return
    - The Security Groups Ids (True)
    - False

## it_has_instance_profile

Check if the EC2 Instance has an Instance Profile
Return
    - The ARN of the instance profile (True)
    - False

## it_has_instance_profile_roles

Check if the EC2 Instance has an Instance Profile and is related to a Role
Return
    - The ARN of the role (True)
    - False

## is_instance_metadata_v2

Check if the EC2 Instance is configured with Instance Metadata Service Version 2 (IMDSv2)
Return
    - True
    - False

# is_instance_metadata_hop_limit_1

Check if the EC2 Instance Metadata is limited to 1 hop
Return
    - True
    - False

## it_has_ebs 

Check if the EC2 Instance has Ebs attached
Return
    - The list of `VolumeId` attached to the instance (True)
    - False

## it_has_unencrypted_ebs

Check if the EC2 Instance has Ebs attached that are unencrypted
Return
    - The list of `VolumeId` attached to the instance that are unencrypted (True)
    - False

## is_attached_to_security_group_rules_unrestricted

Check if the EC2 Instance is attached to Security Groups rules that are unrestricted (open to 0.0.0.0/0 or ::/0)
Return
    - The list of unrestricted rules (True)
    - False

## is_public

Check if the EC2 Instance is public by checking if it_has_public_ip and is_attached_to_security_group_rules_unrestricted
Return 
    - True
    - False

## is_encrypted

Check if the EC2 Instance is encrypted by checking if it_has_unencrypted_ebs:
Return 
    - True
    - False