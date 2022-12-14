"""MetaCheck: AwsEc2SecurityGroup"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from metachecks.checks.Base import MetaChecksBase


class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            region = finding["Region"]
            if not sess:
                self.client = boto3.client("ec2", region_name=region)
            else:
                self.client = sess.client(service_name="ec2", region_name=region)
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.mh_filters_checks = mh_filters_checks
            self.security_groups = self._describe_security_group()
            self.network_interfaces = self._describe_network_interfaces()
            self.rules = self._describe_security_group_rules()

    # Describe Functions

    def _describe_security_group(self):
        response = self.client.describe_security_groups()
        return response["SecurityGroups"]

    def _describe_network_interfaces(self):
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

    def _describe_security_group_rules(self):
        response = self.client.describe_security_group_rules(
            Filters=[
                {
                    "Name": "group-id",
                    "Values": [
                        self.resource_id,
                    ],
                },
            ],
        )
        return response["SecurityGroupRules"]
    
    # MetaChecks

    def its_associated_to_network_interfaces(self):
        NetworkInterfaces = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                NetworkInterfaces.append(NetworkInterface["NetworkInterfaceId"])
            return NetworkInterfaces
        return False

    def its_associated_to_ec2_instances(self):
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

    def its_associated_to_managed_services(self):
        ManagedServices = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                try:
                    RequesterId = NetworkInterface["RequesterManaged"]
                    if RequesterId == True:
                        ManagedServices.append(NetworkInterface["Description"])
                except KeyError:
                    continue
            if ManagedServices:
                return ManagedServices
        return False

    def its_associated_to_ips_public(self):
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

    def its_referenced_by_another_sg(self):
        references = []
        if self.security_groups:
            for sg in self.security_groups:
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

    def it_has_rules_unrestricted(self):
        UnrestrictedRule = []
        if self.rules:
            for rule in self.rules:
                if "CidrIpv4" in rule:
                    if "0.0.0.0/0" in rule["CidrIpv4"] and not rule["IsEgress"]:
                        if rule not in UnrestrictedRule:
                            UnrestrictedRule.append(rule)
                if "CidrIpv6" in rule:
                    if "::/0" in rule["CidrIpv6"] and not rule["IsEgress"]:
                        if rule not in UnrestrictedRule:
                            UnrestrictedRule.append(rule)
        if UnrestrictedRule:
            return UnrestrictedRule
        return False

    def is_public(self):
        if self.its_associated_to_ips_public() and self.it_has_rules_unrestricted():
            return True
        return False

    def is_default(self):
        if self.security_groups:
            for sg in self.security_groups:
                if sg['GroupId'] == self.resource_id:
                    if sg['GroupName'] == "default":
                        return True
        return False

    def checks(self):
        checks = [
            "its_associated_to_network_interfaces",
            "its_associated_to_ec2_instances",
            "its_associated_to_ips_public",
            "its_associated_to_managed_services",
            "its_referenced_by_another_sg",
            "it_has_rules_unrestricted",
            "is_public",
            "is_default"
        ]
        return checks