"""MetaCheck: AwsRdsDbCluster"""

from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import MetaChecksBase


class Metacheck(MetaChecksBase):
    def __init__(
        self,
        logger,
        finding,
        mh_filters_checks,
        sess,
        drilled=False,
    ):
        self.logger = logger
        self.sess = sess
        self.mh_filters_checks = mh_filters_checks
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(self.logger, "rds", self.region, self.sess)
        # Describe
        self.rds_cluster = self.describe_db_clusters()
        if not self.rds_cluster:
            return False
        # Drilled MetaChecks
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

    # MetaChecks

    def endpoint(self):
        if self.rds_cluster:
            if self.rds_cluster.get("Endpoint"):
                return self.rds_cluster.get("Endpoint")
        return False

    def is_encrypted(self):
        if self.rds_cluster:
            if self.rds_cluster.get("StorageEncrypted"):
                return True
        return False

    def is_unrestricted(self):
        if self.iam_roles:
            for role in self.iam_roles:
                if self.iam_roles[role].get("is_unrestricted"):
                    return self.iam_roles[role].get("is_unrestricted")
        return False

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
            "is_encrypted": self.is_encrypted(),
            "is_unrestricted": self.is_unrestricted(),
        }
        return checks
