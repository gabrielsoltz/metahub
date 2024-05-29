"""ResourceType: AwsElbLoadBalancer"""

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
        self.client = get_boto3_client(self.logger, "elb", self.region, self.sess)
        # Describe
        self.elb = self.describe_load_balancers()
        if not self.elb:
            return False
        # Associated MetaChecks
        self.security_groups = self._describe_load_balancers_security_groups()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        if not drilled:
            if (
                "app" in finding["Resources"][0]["Id"]
                or "net" in finding["Resources"][0]["Id"]
            ):
                self.resource_id = finding["Resources"][0]["Id"].split("/")[-2]
            else:
                self.resource_id = finding["Resources"][0]["Id"].split("/")[-1]
        else:
            if "app" in drilled or "net" in drilled:
                self.resource_id = drilled.split("/")[-2]
            else:
                self.resource_id = drilled.split("/")[-1]
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

    # # Context Config
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

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

    def public(self):
        if self.elb.get("Scheme") == "internet-facing":
            return True
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
            "public": self.public(),
            "resource_policy": self.resource_policy(),
        }
        return checks
