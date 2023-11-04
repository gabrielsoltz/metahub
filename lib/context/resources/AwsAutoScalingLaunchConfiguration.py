"""MetaCheck: AwsAutoScalingLaunchConfiguration"""

from aws_arn import generate_arn

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import MetaChecksBase
from lib.context.resources.MetaChecksHelpers import IamHelper


class Metacheck(MetaChecksBase):
    def __init__(
        self,
        logger,
        finding,
        mh_filters_checks,
        sess,
        drilled=False,
    ):
        self.logger = logger
        self.finding = finding
        self.sess = sess
        self.mh_filters_checks = mh_filters_checks
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(
            self.logger, "autoscaling", self.region, self.sess
        )
        # Describe Resource
        self.launch_configuration = self.describe_launch_configuration()
        if not self.launch_configuration:
            return False
        # Drilled MetaChecks
        self.security_groups = self._describe_launch_configuration_security_groups()
        self.iam_roles = self._describe_launch_configuration_iam_roles()
        self.autoscaling_groups = (
            self._describe_launch_configuration_autoscaling_group()
        )

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

    def _describe_launch_configuration_security_groups(self):
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

    def _describe_launch_configuration_iam_roles(self):
        iam_roles = {}
        if self.launch_configuration:
            instance_profile = self.launch_configuration.get("IamInstanceProfile")
            arn = IamHelper(
                self.logger, self.finding, False, self.sess, instance_profile
            ).get_role_from_instance_profile(instance_profile)
            iam_roles[arn] = {}

        return iam_roles

    def _describe_launch_configuration_autoscaling_group(self):
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

    def metadata_options(self):
        metadata_options = False
        if self.launch_configuration:
            metadata_options = self.launch_configuration.get("MetadataOptions")
        return metadata_options

    def associates_public_ip(self):
        associates_public_ip = False
        if self.launch_configuration:
            associates_public_ip = self.launch_configuration.get(
                "AssociatePublicIpAddress"
            )
        return associates_public_ip

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
        if self.autoscaling_groups:
            return True
        return False

    def is_unrestricted(self):
        if self.iam_roles:
            for role in self.iam_roles:
                if self.iam_roles[role].get("is_unrestricted"):
                    return self.iam_roles[role].get("is_unrestricted")
        return False

    def public(self):
        if self.associates_public_ip():
            return True
        return False

    def associations(self):
        associations = {
            "security_groups": self.security_groups,
            "iam_roles": self.iam_roles,
            "autoscaling_groups": self.autoscaling_groups,
        }
        return associations

    def checks(self):
        checks = {
            "metadata_options": self.metadata_options(),
            "associates_public_ip": self.associates_public_ip(),
            "public": self.public(),
            "is_encrypted": self.is_encrypted(),
            "is_attached": self.is_attached(),
            "is_unrestricted": self.is_unrestricted(),
        }
        return checks
