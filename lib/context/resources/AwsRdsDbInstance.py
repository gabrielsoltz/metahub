"""ResourceType: AwsRdsDbInstance"""

from aws_arn import generate_arn
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
        self.client = get_boto3_client(self.logger, "rds", self.region, self.sess)
        # Describe
        self.rds_instances = self.describe_db_instances()
        if not self.rds_instances:
            return False
        # Associated MetaChecks
        self.iam_roles = self._describe_db_instances_iam_roles()
        self.security_groups = self._describe_db_instances_security_groups()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]

    # Describe Functions

    def describe_db_instances(self):
        try:
            response = self.client.describe_db_instances(
                DBInstanceIdentifier=self.resource_id
            )
        except ClientError as err:
            self.logger.error(
                "Failed to describe_db_instances: {}, {}".format(self.resource_id, err)
            )
            return False
        if response["DBInstances"]:
            return response["DBInstances"][0]
        return False

    def _describe_db_instances_iam_roles(self):
        iam_roles = {}
        if self.rds_instances:
            if self.rds_instances.get("AssociatedRoles"):
                for role in self.rds_instances["AssociatedRoles"]:
                    role_arn = role["RoleArn"]
                    iam_roles[role_arn] = {}

        return iam_roles

    def _describe_db_instances_security_groups(self):
        security_groups = {}
        if self.rds_instances:
            if self.rds_instances["VpcSecurityGroups"]:
                for sg in self.rds_instances["VpcSecurityGroups"]:
                    sg_id = sg["VpcSecurityGroupId"]
                    arn = generate_arn(
                        sg_id,
                        "ec2",
                        "security_group",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    security_groups[arn] = {}
        if security_groups:
            return security_groups
        return False

    # Context Config

    def endpoint(self):
        if self.rds_instances:
            if self.rds_instances.get("Endpoint"):
                return self.rds_instances.get("Endpoint")
        return False

    def public(self):
        if self.endpoint():
            return True
        return False

    def storage_encrypted(self):
        if self.rds_instances:
            if self.rds_instances.get("StorageEncrypted"):
                return True
        return False

    def trust_policy(self):
        return None

    def associations(self):
        associations = {
            "iam_roles": self.iam_roles,
            "security_groups": self.security_groups,
        }
        return associations

    def checks(self):
        checks = {
            "endpoint": self.endpoint(),
            "public": self.public(),
            "encrypted": self.storage_encrypted(),
        }
        return checks
