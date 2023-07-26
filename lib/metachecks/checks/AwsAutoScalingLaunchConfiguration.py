"""MetaCheck: AwsAutoScalingLaunchConfiguration"""

from aws_arn import generate_arn

from lib.AwsHelpers import get_boto3_client
from lib.metachecks.checks.Base import MetaChecksBase
from lib.metachecks.checks.MetaChecksHelpers import IamHelper


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
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.mh_filters_checks = mh_filters_checks
            self.client = get_boto3_client(
                self.logger, "autoscaling", self.region, self.sess
            )
            # Describe
            self.launch_configuration = self.describe_launch_configuration()
            if not self.launch_configuration:
                return False
            # Drilled MetaChecks
            self.iam_roles = self.describe_iam_roles()
            self.security_groups = self.describe_security_groups()
            self.autoscaling_group = self.describe_autoscaling_group()

    # Describe functions

    def describe_launch_configuration(self):
        response = self.client.describe_launch_configurations(
            LaunchConfigurationNames=[
                self.resource_id,
            ]
        )
        if response["LaunchConfigurations"]:
            return response["LaunchConfigurations"][0]
        return False

    # Drilled MetaChecks
    # For drilled MetaChecks, describe functions must return a dictionary of resources {arn: {}}

    def describe_security_groups(self):
        security_groups = {}
        if self.launch_configuration:
            if self.launch_configuration["SecurityGroups"]:
                for sg in self.launch_configuration["SecurityGroups"]:
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

    def describe_iam_roles(self):
        iam_roles = {}
        if self.launch_configuration:
            instance_profile = self.launch_configuration.get("IamInstanceProfile")
            arn = IamHelper(
                self.logger, self.finding, False, self.sess, instance_profile
            ).get_role_from_instance_profile(instance_profile)
            iam_roles[arn] = {}

        return iam_roles

    def describe_autoscaling_group(self):
        autoscaling_group = {}
        if self.launch_configuration:
            response = self.client.describe_auto_scaling_groups()
            if response.get("AutoScalingGroups"):
                for asg in response["AutoScalingGroups"]:
                    try:
                        if asg["LaunchConfigurationName"] == self.resource_id:
                            autoscaling_group[asg["AutoScalingGroupARN"]] = {}
                    except KeyError:
                        # No LaunchTemplate
                        continue
        return autoscaling_group

    # MetaChecks

    def its_associated_with_autoscaling_group(self):
        if self.autoscaling_group:
            return self.autoscaling_group
        return False

    def is_instance_metadata_v2(self):
        HttpTokens = False
        if self.launch_configuration:
            try:
                HttpTokens = self.launch_configuration["MetadataOptions"]["HttpTokens"]
            except KeyError:
                HttpTokens = False
            if HttpTokens == "required":
                return True
        return False

    def is_instance_metadata_hop_limit_1(self):
        HttpPutResponseHopLimit = False
        if self.launch_configuration:
            try:
                HttpPutResponseHopLimit = self.launch_configuration["MetadataOptions"][
                    "HttpPutResponseHopLimit"
                ]
            except KeyError:
                HttpPutResponseHopLimit = False
            if HttpPutResponseHopLimit == 1:
                return True
        return False

    def its_associated_with_security_groups(self):
        if self.security_groups:
            return self.security_groups
        return False

    def its_associated_with_iam_roles(self):
        if self.iam_roles:
            return self.iam_roles
        return False

    def it_associates_public_ip(self):
        PublicIp = False
        if self.launch_configuration:
            try:
                PublicIp = self.launch_configuration["AssociatePublicIpAddress"]
            except KeyError:
                PublicIp = False
        return PublicIp

    def is_public(self):
        sg_ingress_unrestricted = False
        for sg in self.security_groups:
            if self.security_groups[sg].get("is_ingress_rules_unrestricted"):
                sg_ingress_unrestricted = True
        if self.it_associates_public_ip() and sg_ingress_unrestricted:
            return True
        return False

    def is_encrypted(self):
        if self.launch_configuration:
            if self.launch_configuration["BlockDeviceMappings"]:
                for device in self.launch_configuration["BlockDeviceMappings"]:
                    if (
                        device.get("Ebs").get("Encrypted")
                        and device.get("Ebs").get("Encrypted") is True
                    ):
                        continue
                    else:
                        return False
        return True

    def is_attached(self):
        if self.its_associated_with_autoscaling_group():
            return True
        return False

    def checks(self):
        checks = [
            "is_instance_metadata_v2",
            "is_instance_metadata_hop_limit_1",
            "its_associated_with_autoscaling_group",
            "its_associated_with_security_groups",
            "its_associated_with_iam_roles",
            "it_associates_public_ip",
            "is_public",
            "is_encrypted",
            "is_attached",
        ]
        return checks
