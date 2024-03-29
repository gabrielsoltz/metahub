"""ResourceType: AwsEc2SecurityGroup"""

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
        self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
        # Describe Resource
        self.all_security_group = self.describe_security_groups()
        self.security_group = self._describe_security_group()
        if not self.security_group:
            return False
        self.all_network_interfaces = self.describe_network_interfaces()
        self.network_interfaces = self._describe_network_interfaces_interfaces()
        self.instances = self._describe_network_interfaces_instances()
        self.security_group_rules = self.describe_security_group_rules()
        # Associated MetaChecks
        self.vpcs = self._describe_security_group_vpc()

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

    def describe_security_groups(self):
        try:
            response = self.client.describe_security_groups()
            if response["SecurityGroups"]:
                return response["SecurityGroups"]
        except ClientError as err:
            if not err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.error(
                    "Failed to describe_security_groups: {}, {}".format(
                        self.resource_id, err
                    )
                )
        return False

    def _describe_security_group(self):
        if self.all_security_group:
            for sg in self.all_security_group:
                if sg["GroupId"] == self.resource_id:
                    return sg
        return False

    def describe_network_interfaces(self):
        response = self.client.describe_network_interfaces(
            Filters=[
                {
                    "Name": "group-id",
                    "Values": [
                        self.resource_id,
                    ],
                },
            ],
        )
        return response["NetworkInterfaces"]

    def _describe_network_interfaces_interfaces(self):
        network_interfaces = {}
        if self.all_network_interfaces:
            for network_interface in self.all_network_interfaces:
                arn = generate_arn(
                    network_interface["NetworkInterfaceId"],
                    "ec2",
                    "network_interface",
                    self.region,
                    self.account,
                    self.partition,
                )
                network_interfaces[arn] = {}
        return network_interfaces

    def _describe_network_interfaces_instances(self):
        instances = {}
        if self.all_network_interfaces:
            for network_interface in self.all_network_interfaces:
                if network_interface.get("Attachment") and network_interface.get(
                    "Attachment"
                ).get("InstanceId"):
                    arn = generate_arn(
                        network_interface.get("Attachment").get("InstanceId"),
                        "ec2",
                        "instance",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    instances[arn] = {}
        return instances

    def describe_security_group_rules(self):
        security_group_rules = []
        if self.security_group:
            response = self.client.describe_security_group_rules(
                Filters=[
                    {"Name": "group-id", "Values": [self.resource_id]},
                ],
            )
            if response["SecurityGroupRules"]:
                security_group_rules = response["SecurityGroupRules"]
        return security_group_rules

    def _describe_security_group_vpc(self):
        vcps = {}
        if self.security_group:
            arn = generate_arn(
                self.security_group["VpcId"],
                "ec2",
                "vpc",
                self.region,
                self.account,
                self.partition,
            )
            vcps[arn] = {}
        return vcps

    def managed_services(self):
        managed_services = []
        if self.all_network_interfaces:
            for network_interface in self.all_network_interfaces:
                if network_interface.get("RequesterManaged"):
                    managed_services.append(network_interface.get("Description"))
        return managed_services

    def public_ips(self):
        public_ips = []
        if self.all_network_interfaces:
            for network_interface in self.all_network_interfaces:
                if network_interface.get("Association"):
                    public_ips.append(
                        network_interface.get("Association").get("PublicIp")
                    )
        return public_ips

    def its_referenced_by_a_security_group(self):
        references = []
        if self.all_security_group:
            for sg in self.all_security_group:
                GroupId = sg["GroupId"]
                IpPermissions = sg["IpPermissions"]
                IpPermissionsEgress = sg["IpPermissionsEgress"]
                for rule in IpPermissions:
                    for sub_rule in rule["UserIdGroupPairs"]:
                        if self.resource_id in sub_rule["GroupId"]:
                            references.append(GroupId)
                for rule in IpPermissionsEgress:
                    for sub_rule in rule["UserIdGroupPairs"]:
                        if self.resource_id in sub_rule["GroupId"]:
                            references.append(GroupId)
        if references:
            return references
        return False

    def default(self):
        if self.security_group:
            if self.security_group["GroupName"] == "default":
                return True
        return False

    def attached(self):
        if self.security_group:
            if self.network_interfaces:
                return True
        return False

    def associations(self):
        associations = {
            "vpcs": self.vpcs,
            "network_interfaces": self.network_interfaces,
            "instances": self.instances,
        }
        return associations

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

    def public(self):
        if self.public_ips():
            return True
        return False

    def checks(self):
        checks = {
            "public_ips": self.public_ips(),
            "managed_services": self.managed_services(),
            "its_referenced_by_a_security_group": self.its_referenced_by_a_security_group(),
            "security_group_rules": self.security_group_rules,
            "public": self.public(),
            "default": self.default(),
            "attached": self.attached(),
            "resource_policy": self.resource_policy(),
        }
        return checks
