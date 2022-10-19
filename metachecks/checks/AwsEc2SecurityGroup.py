"""MetaCheck: AwsEc2SecurityGroup"""

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class Metacheck:
    def __init__(self, logger, finding, mh_filters, sess):
        self.logger = logger
        if not sess:
            self.client = boto3.client("ec2")
        else:
            self.client = sess.client(service_name="ec2")
        if finding:
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.security_groups = self._describe_security_group()
            self.network_interfaces = self._describe_network_interfaces()
            self.mh_filters = mh_filters
            self.tags = self._tags()
            self.tags_all = self._parse_tags()

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

    def _tags(self):
        response = self.client.describe_tags(
            Filters=[
                {
                    "Name": "resource-id",
                    "Values": [
                        self.resource_id,
                    ],
                },
            ],
        )
        return response["Tags"]

    def _find_tag(self, tag):
        if self.tags:
            for _tag in self.tags:
                if _tag["Key"] == tag:
                    return _tag["Value"]
        return False

    def _parse_tags(self):
        _tags = {}
        if self.tags:
            for tag in self.tags:
                _tags.update({tag["Key"]: tag["Value"]})
        return _tags

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

    def output(self):
        mh_values = {}
        mh_matched = False if self.mh_filters else True

        for check in self.checks():
            hndl = getattr(self, check)()
            mh_values.update({check: hndl})
            if check in self.mh_filters:
                self.logger.info(
                    "Evaluating MetaCheck filter ("
                    + check
                    + "). Expected: "
                    + str(self.mh_filters[check])
                    + " Found: "
                    + str(bool(hndl))
                )
                if self.mh_filters[check] and bool(hndl):
                    mh_matched = True
                if not self.mh_filters[check] and not hndl:
                    mh_matched = True

        # Tags
        mh_values.update({"tags": self.tags_all})

        return mh_values, mh_matched
