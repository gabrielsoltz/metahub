"""MetaCheck: AwsRdsDbCluster"""

from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.metachecks.checks.Base import MetaChecksBase


class Metacheck(MetaChecksBase):
    def __init__(
        self,
        logger,
        finding,
        metachecks,
        mh_filters_checks,
        sess,
        drilled=False,
    ):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = finding["Resources"][0]["Id"].split(":")[1]
            self.finding = finding
            self.sess = sess
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split(":")[-1]
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "rds", self.region, self.sess)
            # Describe
            self.rds_cluster = self.describe_db_clusters()
            # Drilled MetaChecks
            self.iam_roles = self.describe_iam_roles()
            self.security_groups = self.describe_security_groups()

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

    # Drilled MetaChecks
    # For drilled MetaChecks, describe functions must return a dictionary of resources {arn: {}}

    def describe_security_groups(self):
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

    def describe_iam_roles(self):
        iam_roles = {}
        if self.rds_cluster:
            if self.rds_cluster.get("AssociatedRoles"):
                for role in self.rds_cluster["AssociatedRoles"]:
                    role_arn = role["RoleArn"]
                    iam_roles[role_arn] = {}

        return iam_roles

    # MetaChecks

    def its_associated_with_iam_roles(self):
        if self.rds_cluster:
            return self.iam_roles
        return False

    def its_associated_with_security_groups(self):
        if self.rds_cluster:
            return self.security_groups
        return False

    def it_has_endpoint(self):
        if self.rds_cluster:
            if self.rds_cluster.get("Endpoint"):
                return self.rds_cluster.get("Endpoint")
        return False

    def is_public(self):
        public_dict = {}
        if self.it_has_endpoint():
            for sg in self.security_groups:
                if self.security_groups[sg].get("is_ingress_rules_unrestricted"):
                    public_dict[self.it_has_endpoint()] = []
                    for rule in self.security_groups[sg].get("is_ingress_rules_unrestricted"):
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        ip_protocol = rule.get("IpProtocol")
                        public_dict[self.it_has_endpoint()].append({"from_port": from_port, "to_port": to_port, "ip_protocol": ip_protocol})
            if public_dict:
                return public_dict
        return False

    def is_encrypted(self):
        if self.rds_cluster:
            if self.rds_cluster.get("StorageEncrypted"):
                return True
        return False

    def checks(self):
        checks = [
            "its_associated_with_iam_roles",
            "its_associated_with_security_groups",
            "is_public",
            "is_encrypted",
        ]
        return checks
