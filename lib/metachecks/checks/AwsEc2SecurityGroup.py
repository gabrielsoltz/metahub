"""MetaCheck: AwsEc2SecurityGroup"""

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
            self.resource_id = (
                finding["Resources"][0]["Id"].split("/")[1]
                if not drilled
                else drilled.split("/")[1]
            )
            self.resource_arn = (
                finding["Resources"][0]["Id"] if not drilled else drilled
            )
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
            # Describe
            self.all_security_group = self.describe_security_groups()
            self.network_interfaces = self.describe_network_interfaces()
            self.security_group_rules = self.describe_security_group_rules()
            # Drilled MetaChecks

    # Describe Functions

    def describe_security_groups(self):
        try:
            response = self.client.describe_security_groups()
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.info(
                    "Failed to describe_security_groups: {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False
            else:
                self.logger.error(
                    "Failed to describe_security_groups: {}, {}".format(
                        self.resource_id, err
                    )
                )
                return False
        if response["SecurityGroups"]:
            return response["SecurityGroups"]
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

    def describe_security_group_rules(self):
        response = self.client.describe_security_group_rules(
            Filters=[
                {"Name": "group-id", "Values": [self.resource_id]},
            ],
        )
        if response["SecurityGroupRules"]:
            return response["SecurityGroupRules"]
        return False

    # MetaChecks

    def its_associated_with_network_interfaces(self):
        NetworkInterfaces = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                NetworkInterfaces.append(NetworkInterface["NetworkInterfaceId"])
            return NetworkInterfaces
        return False

    def its_associated_with_ec2_instances(self):
        Ec2Instances = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                try:
                    Ec2Instances.append(NetworkInterface["Attachment"]["InstanceId"])
                except KeyError:
                    continue
            if Ec2Instances:
                return Ec2Instances
        return False

    def its_associated_with_managed_services(self):
        ManagedServices = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                try:
                    RequesterId = NetworkInterface["RequesterManaged"]
                    if RequesterId:
                        ManagedServices.append(NetworkInterface["Description"])
                except KeyError:
                    continue
            if ManagedServices:
                return ManagedServices
        return False

    def its_associated_with_ips_public(self):
        PublicIPs = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                try:
                    PublicIPs.append(NetworkInterface["Association"]["PublicIp"])
                except KeyError:
                    continue
            if PublicIPs:
                return PublicIPs
        return False

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

    def is_ingress_rule_unrestricted(self, rule):
        """ """
        if "CidrIpv4" in rule:
            if "0.0.0.0/0" in rule["CidrIpv4"] and not rule["IsEgress"]:
                return True
        if "CidrIpv6" in rule:
            if "::/0" in rule["CidrIpv6"] and not rule["IsEgress"]:
                return True
        return False

    def is_egress_rule_unrestricted(self, rule):
        """ """
        if "CidrIpv4" in rule:
            if "0.0.0.0/0" in rule["CidrIpv4"] and rule["IsEgress"]:
                return True
        if "CidrIpv6" in rule:
            if "::/0" in rule["CidrIpv6"] and rule["IsEgress"]:
                return True
        return False

    def check_security_group(self):
        failed_rules = {
            "is_ingress_rules_unrestricted": [],
            "is_egress_rules_unrestricted": [],
        }
        if self.security_group_rules:
            for rule in self.security_group_rules:
                if (
                    self.is_ingress_rule_unrestricted(rule)
                    and rule not in failed_rules["is_ingress_rules_unrestricted"]
                ):
                    failed_rules["is_ingress_rules_unrestricted"].append(rule)
                if (
                    self.is_egress_rule_unrestricted(rule)
                    and rule not in failed_rules["is_egress_rules_unrestricted"]
                ):
                    failed_rules["is_egress_rules_unrestricted"].append(rule)
        return failed_rules

    def is_ingress_rules_unrestricted(self):
        is_ingress_rules_unrestricted = self.check_security_group()[
            "is_ingress_rules_unrestricted"
        ]
        if is_ingress_rules_unrestricted:
            return is_ingress_rules_unrestricted
        return False

    def is_egress_rules_unrestricted(self):
        is_egress_rules_unrestricted = self.check_security_group()[
            "is_egress_rules_unrestricted"
        ]
        if is_egress_rules_unrestricted:
            return is_egress_rules_unrestricted
        return False

    def is_public(self):
        public_dict = {}
        if self.its_associated_with_ips_public() and self.is_ingress_rules_unrestricted():
            for ip in self.its_associated_with_ips_public():
                public_dict[ip] = []
                if self.is_ingress_rules_unrestricted():
                    for rule in self.is_ingress_rules_unrestricted():
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        ip_protocol = rule.get("IpProtocol")
                        public_dict[ip].append({"from_port": from_port, "to_port": to_port, "ip_protocol": ip_protocol})
        if public_dict:
            return public_dict
        return False

    def is_default(self):
        if self.all_security_group:
            for sg in self.all_security_group:
                if sg["GroupId"] == self.resource_id:
                    if sg["GroupName"] == "default":
                        return True
        return False

    def checks(self):
        checks = [
            "its_associated_with_network_interfaces",
            "its_associated_with_ec2_instances",
            "its_associated_with_ips_public",
            "its_associated_with_managed_services",
            "its_referenced_by_a_security_group",
            "is_ingress_rules_unrestricted",
            "is_egress_rules_unrestricted",
            "is_public",
            "is_default",
        ]
        return checks
