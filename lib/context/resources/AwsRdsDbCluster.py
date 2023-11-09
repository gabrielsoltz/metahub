"""ResourceType: AwsRdsDbCluster"""

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
        self.rds_cluster = self.describe_db_clusters()
        if not self.rds_cluster:
            return False
        # Associated MetaChecks
        self.iam_roles = self._describe_db_clusters_iam_roles()
        self.security_groups = self._describe_db_clusters_security_groups()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]

    # Describe Functions

    def describe_db_clusters(self):
        try:
            response = self.client.describe_db_clusters(
                DBClusterIdentifier=self.resource_id
            )
        except ClientError as err:
            self.logger.error(
                "Failed to describe_db_clusters: {}, {}".format(self.resource_id, err)
            )
            return False
        if response["DBClusters"]:
            return response["DBClusters"][0]
        return False

    def _describe_db_clusters_security_groups(self):
        security_groups = {}
        if self.rds_cluster:
            if self.rds_cluster["VpcSecurityGroups"]:
                for sg in self.rds_cluster["VpcSecurityGroups"]:
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

    def _describe_db_clusters_iam_roles(self):
        iam_roles = {}
        if self.rds_cluster:
            if self.rds_cluster.get("AssociatedRoles"):
                for role in self.rds_cluster["AssociatedRoles"]:
                    role_arn = role["RoleArn"]
                    iam_roles[role_arn] = {}

        return iam_roles

    # Context Config

    def endpoint(self):
        if self.rds_cluster:
            if self.rds_cluster.get("PubliclyAccessible"):
                return self.rds_cluster.get("PubliclyAccessible")
        return False

    def storage_encrypted(self):
        if self.rds_cluster:
            if self.rds_cluster.get("StorageEncrypted"):
                return True
        return False

    def trust_policy(self):
        return None

    def public(self):
        if self.endpoint():
            return True
        return False

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
