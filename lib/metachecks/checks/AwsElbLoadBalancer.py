"""MetaCheck: AwsElbLoadBalancer"""

from aws_arn import generate_arn
from botocore.exceptions import ClientError
from lib.AwsHelpers import get_boto3_client
from lib.metachecks.checks.Base import MetaChecksBase
import json
from lib.metachecks.checks.MetaChecksHelpers import PolicyHelper


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
            self.resource_id = (
                finding["Resources"][0]["Id"].split("/")[-1]
                if not drilled
                else drilled.split("/")[-11]
            )
            self.resource_arn = (
                finding["Resources"][0]["Id"] if not drilled else drilled
            )
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(
                self.logger, "elb", self.region, self.sess
            )
            # Describe
            self.elb = self.describe_load_balancers()
            if not self.elb:
                return False
            # Drilled MetaChecks
            self.security_groups = self.describe_security_groups()

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
                    "Failed to describe_load_balancers: {}, {}".format(self.resource_id, err)
                )
            return False
        return response

    # Drilled MetaChecks

    def describe_security_groups(self):
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
    def it_has_name(self):
        if self.elb.get("LoadBalancerName"):
            return self.elb.get("LoadBalancerName")
        return False

    def it_has_endpoint(self):
        if self.elb.get("DNSName"):
            return self.elb.get("DNSName")
        return False
    
    def it_has_scheme(self):
        if self.elb.get("Scheme"):
            return self.elb.get("Scheme")
        return False
    
    # Drilled MetaChecks

    def its_associated_with_security_groups(self):
        if self.security_groups:
            return self.security_groups
        return False
    
    def is_public(self):
        public_dict = {}
        if self.elb.get("Scheme") == "internet-facing":
            for sg in self.security_groups:
                if self.security_groups[sg].get("is_ingress_rules_unrestricted"):
                    public_dict[self.it_has_endpoint()] = []
                    for rule in self.security_groups[sg].get(
                        "is_ingress_rules_unrestricted"
                    ):
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        ip_protocol = rule.get("IpProtocol")
                        public_dict[self.it_has_endpoint()].append(
                            {
                                "from_port": from_port,
                                "to_port": to_port,
                                "ip_protocol": ip_protocol,
                            }
                        )
        if public_dict:
            return public_dict
        return False

    def checks(self):
        checks = [
            "it_has_name",
            "it_has_endpoint",
            "it_has_scheme",
            "its_associated_with_security_groups",
            "is_public",
        ]
        return checks