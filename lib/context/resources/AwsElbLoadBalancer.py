"""MetaCheck: AwsElbLoadBalancer"""

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
        self.client = get_boto3_client(self.logger, "elb", self.region, self.sess)
        # Describe
        self.elb = self.describe_load_balancers()
        if not self.elb:
            return False
        # Drilled MetaChecks
        self.security_groups = self._describe_load_balancers_security_groups()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[-1]
            if not drilled
            else drilled.split("/")[-11]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled

    # Describe function

    def describe_load_balancers(self):
        try:
            response = self.client.describe_load_balancers(
                LoadBalancerNames=[
                    self.resource_id,
                ],
            ).get("LoadBalancerDescriptions")[0]
        except ClientError as err:
            if not err.response["Error"]["Code"] == "LoadBalancerNotFound":
                self.logger.error(
                    "Failed to describe_load_balancers: {}, {}".format(
                        self.resource_id, err
                    )
                )
            return False
        return response

    def _describe_load_balancers_security_groups(self):
        security_groups = {}
        if self.elb:
            if self.elb.get("SecurityGroups"):
                for sg in self.elb["SecurityGroups"]:
                    arn = generate_arn(
                        sg,
                        "ec2",
                        "security_group",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    security_groups[arn] = {}

        return security_groups

    # # MetaChecks
    def name(self):
        if self.elb.get("LoadBalancerName"):
            return self.elb.get("LoadBalancerName")
        return False

    def endpoint(self):
        if self.elb.get("DNSName"):
            return self.elb.get("DNSName")
        return False

    def scheme(self):
        if self.elb.get("Scheme"):
            return self.elb.get("Scheme")
        return False

    def is_public(self):
        public_dict = {}
        if self.elb.get("Scheme") == "internet-facing":
            for sg in self.security_groups:
                if self.security_groups[sg].get("is_ingress_rules_unrestricted"):
                    public_dict[self.endpoint()] = []
                    for rule in self.security_groups[sg].get(
                        "is_ingress_rules_unrestricted"
                    ):
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        ip_protocol = rule.get("IpProtocol")
                        public_dict[self.endpoint()].append(
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
            "security_groups": self.security_groups,
        }
        return associations

    def checks(self):
        checks = {
            "name": self.name(),
            "endpoint": self.endpoint(),
            "scheme": self.scheme(),
            "is_public": self.is_public(),
        }
        return checks
