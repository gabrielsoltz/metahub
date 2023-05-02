"""MetaCheck: AwsEc2SecurityGroup"""

import boto3
from botocore.exceptions import ClientError

from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import SecurityGroupChecker


class Metacheck(MetaChecksBase):
    def __init__(
        self, logger, finding, metachecks, mh_filters_checks, sess, drilled=False
    ):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = finding["Resources"][0]["Id"].split(":")[1]
            self.finding = finding
            self.sess = sess
            self.mh_filters_checks = mh_filters_checks
            if not sess:
                self.client = boto3.client("ec2", region_name=self.region)
            else:
                self.client = sess.client(service_name="ec2", region_name=self.region)
            if not drilled:
                self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
                self.resource_arn = finding["Resources"][0]["Id"]
            if drilled:
                self.resource_id = drilled.split("/")[1]
                self.resource_arn = drilled
            self.mh_filters_checks = mh_filters_checks
            self.security_groups = self._describe_security_group()
            self.network_interfaces = self._describe_network_interfaces()
            self.checked_security_group = SecurityGroupChecker(
                self.logger, finding, {self.resource_arn}, sess
            ).check_security_group()

    # Describe Functions

    def _describe_security_group(self):
        try:
            response = self.client.describe_security_groups()
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                self.logger.info(
                    "Failed to describe_security_groups: {}, {}".format(self.resource_id, err)
                )
                return False
            else:
                self.logger.error(
                    "Failed to describe_security_groups: {}, {}".format(self.resource_id, err)
                )
                return False
        if response["SecurityGroups"]:
            return response["SecurityGroups"]
        return False

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

    def is_ingress_rules_unrestricted(self):
        if self.checked_security_group["is_ingress_rules_unrestricted"]:
            return self.checked_security_group["is_ingress_rules_unrestricted"]
        return False

    def is_egress_rules_unrestricted(self):
        if self.checked_security_group["is_egress_rule_unrestricted"]:
            return self.checked_security_group["is_egress_rule_unrestricted"]
        return False

    def is_public(self):
        if (
            self.its_associated_with_ips_public()
            and self.is_ingress_rules_unrestricted()
        ):
            return True
        return False

    def is_default(self):
        if self.security_groups:
            for sg in self.security_groups:
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
