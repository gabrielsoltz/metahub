"""MetaCheck: AwsEksCluster"""

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
        self.client = get_boto3_client(self.logger, "eks", self.region, self.sess)
        # Describe
        self.eks_cluster = self.describe_cluster()
        if not self.eks_cluster:
            return False
        # Drilled MetaChecks
        self.iam_roles = self._describe_cluster_iam_roles()
        self.security_groups = self._describe_cluster_security_groups()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[1]
            if not drilled
            else drilled.split("/")[1]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled

    # Describe Functions

    def describe_cluster(self):
        try:
            response = self.client.describe_cluster(name=self.resource_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.info(
                    "Failed to describe_cluster: {}, {}".format(self.resource_id, err)
                )
                return False
            else:
                self.logger.error(
                    "Failed to describe_cluster: {}, {}".format(self.resource_id, err)
                )
                return False
        if response["cluster"]:
            return response["cluster"]
        return False

    def _describe_cluster_security_groups(self):
        security_groups = {}
        if self.eks_cluster:
            if self.eks_cluster["resourcesVpcConfig"]["securityGroupIds"]:
                for security_group_id in self.eks_cluster["resourcesVpcConfig"][
                    "securityGroupIds"
                ]:
                    arn = generate_arn(
                        security_group_id,
                        "ec2",
                        "security_group",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    security_groups[arn] = {}
            if self.eks_cluster["resourcesVpcConfig"]["clusterSecurityGroupId"]:
                security_group_id = self.eks_cluster["resourcesVpcConfig"][
                    "clusterSecurityGroupId"
                ]
                arn = generate_arn(
                    security_group_id,
                    "ec2",
                    "security_group",
                    self.region,
                    self.account,
                    self.partition,
                )
                security_groups[arn] = {}

        return security_groups

    def _describe_cluster_iam_roles(self):
        iam_roles = {}
        if self.eks_cluster:
            if self.eks_cluster["roleArn"]:
                role_arn = self.eks_cluster["roleArn"]
                iam_roles[role_arn] = {}

        return iam_roles

    # MetaChecks Functions

    def endpoint(self):
        if self.eks_cluster:
            return self.eks_cluster.get("endpoint", False)
        return False

    def public_endpoint(self):
        if self.eks_cluster:
            if self.eks_cluster["resourcesVpcConfig"]["endpointPublicAccess"]:
                return self.eks_cluster.get("endpoint", False)
        return False

    def is_public(self):
        public_dict = {}
        if self.public_endpoint():
            for sg in self.security_groups:
                if self.security_groups[sg].get("is_ingress_rules_unrestricted"):
                    public_dict[self.public_endpoint()] = []
                    for rule in self.security_groups[sg].get(
                        "is_ingress_rules_unrestricted"
                    ):
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        ip_protocol = rule.get("IpProtocol")
                        public_dict[self.public_endpoint()].append(
                            {
                                "from_port": from_port,
                                "to_port": to_port,
                                "ip_protocol": ip_protocol,
                            }
                        )
        if public_dict:
            return public_dict
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
            "public_endpoint": self.public_endpoint(),
            "is_public": self.is_public(),
        }
        return checks
