"""MetaCheck: AwsEc2SecurityGroup"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from metachecks.checks.Base import MetaChecksBase


class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if not sess:
            self.client = boto3.client("ec2")
        else:
            self.client = sess.client(service_name="ec2")
        if metachecks:
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.mh_filters_checks = mh_filters_checks
            self.security_groups = self._describe_security_group()
            self.network_interfaces = self._describe_network_interfaces()

    def _describe_security_group(self):
        response = self.client.describe_security_groups()
        return response["SecurityGroups"]

    def _check_security_group_exists_in_account(self):
        for sg in self.security_groups:
            if self.resource_id == sg["GroupId"]:
                return True
        self.logger.error(
            "We couldn't find SG %s in AWS account. Try using --mh-assume-role...",
            self.resource_id,
        )
        return False

    def _describe_network_interfaces(self):
        if self._check_security_group_exists_in_account():
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
        return False

    def _describe_security_group_rules(self):
        if self._check_security_group_exists_in_account():
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
        return False

    def is_referenced_by_another_sg(self):
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

    def is_attached_to_network_interfaces(self):
        NetworkInterfaces = []
        if self.network_interfaces:
            for NetworkInterface in self.network_interfaces:
                NetworkInterfaces.append(NetworkInterface["NetworkInterfaceId"])
            return NetworkInterfaces
        return False

    def is_attached_to_ec2_instances(self):
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

    def is_attached_to_managed_services(self):
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

    def is_attached_to_public_ips(self):
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

    def is_public(self):
        if self.is_attached_to_public_ips():
            return True
        return False

    def checks(self):
        checks = [
            "is_attached_to_network_interfaces",
            "is_attached_to_ec2_instances",
            "is_attached_to_public_ips",
            "is_attached_to_managed_services",
            "is_public",
            "is_referenced_by_another_sg",
        ]
        return checks
