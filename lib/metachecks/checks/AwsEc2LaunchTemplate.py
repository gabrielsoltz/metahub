"""MetaCheck: AwsEc2LaunchTemplate"""

import boto3
from aws_arn import generate_arn

from lib.metachecks.checks.Base import MetaChecksBase


class Metacheck(MetaChecksBase):
    def __init__(
        self,
        logger,
        finding,
        metachecks,
        mh_filters_checks,
        sess,
        drilled_down,
        drilled=False,
    ):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = finding["Resources"][0]["Id"].split(":")[1]
            self.finding = finding
            self.sess = sess
            if not sess:
                self.client = boto3.client("ec2", region_name=self.region)
                self.asg_client = boto3.client("autoscaling", region_name=self.region)
            else:
                self.client = sess.client(service_name="ec2", region_name=self.region)
                self.asg_client = sess.client(
                    service_name="autoscaling", region_name=self.region
                )
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.mh_filters_checks = mh_filters_checks
            self.launch_template = self._describe_launch_template_versions()
            self.auto_scaling_groups = self._describe_auto_scaling_groups()
            # Drilled MetaChecks
            self.security_groups = self.describe_security_groups()
            if drilled_down:
                self.execute_drilled_metachecks()

    # Describe functions

    def _describe_launch_template_versions(self):
        response = self.client.describe_launch_template_versions(
            LaunchTemplateId=self.resource_id
        )
        if response["LaunchTemplateVersions"]:
            for version in response["LaunchTemplateVersions"]:
                if version["DefaultVersion"]:
                    return version
        return False

    def _describe_auto_scaling_groups(self):
        response = self.asg_client.describe_auto_scaling_groups()
        if response["AutoScalingGroups"]:
            return response["AutoScalingGroups"]
        return False

    # Drilled MetaChecks
    # For drilled MetaChecks, describe functions must return a dictionary of resources {arn: {}}

    def describe_security_groups(self):
        security_groups = {}
        if self.launch_template:
            if self.launch_template.get("LaunchTemplateData").get("SecurityGroupIds"):
                for sg in self.launch_template.get("LaunchTemplateData").get(
                    "SecurityGroupIds"
                ):
                    arn = generate_arn(
                        sg,
                        "ec2",
                        "security_group",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    security_groups[arn] = {}
        if security_groups:
            return security_groups
        return False

    # MetaChecks

    def its_associated_with_an_asg(self):
        ASGS = []
        if self.auto_scaling_groups:
            for asg in self.auto_scaling_groups:
                try:
                    if asg["LaunchTemplate"]["LaunchTemplateId"] == self.resource_id:
                        ASGS.append(asg["AutoScalingGroupARN"])
                except KeyError:
                    # No LaunchTemplate
                    continue
        if ASGS:
            return ASGS
        return False

    def its_associated_with_asg_instances(self):
        ASGSINSTANCES = []
        if self.its_associated_with_an_asg():
            for asg in self.auto_scaling_groups:
                if asg["LaunchTemplate"]["LaunchTemplateId"] == self.resource_id:
                    if asg["Instances"]:
                        for instance in asg["Instances"]:
                            ASGSINSTANCES.append(instance["InstanceId"])
        if ASGSINSTANCES:
            return ASGSINSTANCES
        return False

    def is_instance_metadata_v2(self):
        HttpTokens = False
        if self.launch_template:
            try:
                HttpTokens = self.launch_template["LaunchTemplateData"][
                    "MetadataOptions"
                ]["HttpTokens"]
            except KeyError:
                HttpTokens = False
            if HttpTokens == "required":
                return True
        return False

    def is_instance_metadata_hop_limit_1(self):
        HttpPutResponseHopLimit = False
        if self.launch_template:
            try:
                HttpPutResponseHopLimit = self.launch_template["LaunchTemplateData"][
                    "MetadataOptions"
                ]["HttpPutResponseHopLimit"]
            except KeyError:
                HttpPutResponseHopLimit = False
            if HttpPutResponseHopLimit == 1:
                return True
        return False

    def it_has_name(self):
        if self.launch_template:
            try:
                Name = self.launch_template["LaunchTemplateName"]
            except KeyError:
                Name = False
        return Name

    def its_associated_with_security_groups(self):
        if self.security_groups:
            return self.security_groups
        return False

    def it_has_public_ip(self):
        PublicIp = False
        if self.launch_template:
            try:
                for network_interface in self.launch_template["LaunchTemplateData"][
                    "NetworkInterfaces"
                ]:
                    if network_interface["AssociatePublicIpAddress"]:
                        PublicIp = True
            except KeyError:
                PublicIp = False
        return PublicIp

    def is_public(self):
        ingress_unrestricted = False
        if self.security_groups:
            for sg in self.security_groups:
                if self.security_groups[sg]["is_ingress_rules_unrestricted"]:
                    ingress_unrestricted = True
        if self.it_has_public_ip() and ingress_unrestricted:
            return self.it_has_public_ip()
        return False

    def is_encrypted(self):
        if self.launch_template:
            if self.launch_template.get("LaunchTemplateData").get(
                "BlockDeviceMappings"
            ):
                for device in self.launch_template.get("LaunchTemplateData").get(
                    "BlockDeviceMappings"
                ):
                    if (
                        device.get("Ebs").get("Encrypted")
                        and device.get("Ebs").get("Encrypted") is True
                    ):
                        continue
                    else:
                        return False
        return True

    def checks(self):
        checks = [
            "is_instance_metadata_v2",
            "is_instance_metadata_hop_limit_1",
            "its_associated_with_an_asg",
            "its_associated_with_asg_instances",
            "it_has_name",
            "its_associated_with_security_groups",
            "it_has_public_ip",
            "is_public",
            "is_encrypted",
        ]
        return checks
