"""ResourceType: AwsEc2LaunchTemplate"""

from aws_arn import generate_arn

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import ContextBase
from lib.context.resources.ContextHelpers import IamHelper


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
        self.finding = finding
        self.sess = sess
        self.mh_filters_config = mh_filters_config
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
        self.asg_client = get_boto3_client(
            self.logger, "autoscaling", self.region, self.sess
        )
        # Describe Resource
        self.launch_template = self.describe_launch_template_versions()
        if not self.launch_template:
            return False
        self.launch_template_data = (
            self._describe_launch_template_versions_launch_template_data()
        )
        # Associated MetaChecks
        self.security_groups = self._describe_launch_template_versions_security_groups()
        self.iam_roles = self._describe_launch_template_versions_iam_roles()
        self.autoscaling_groups = self.describe_auto_scaling_groups()

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split("/")[1]

    # Describe functions

    def describe_launch_template_versions(self):
        response = self.client.describe_launch_template_versions(
            LaunchTemplateId=self.resource_id
        )
        if response["LaunchTemplateVersions"]:
            for version in response["LaunchTemplateVersions"]:
                if version["DefaultVersion"]:
                    return version
        return False

    def _describe_launch_template_versions_launch_template_data(self):
        launch_template_data = False
        if self.launch_template:
            launch_template_data = self.launch_template.get("LaunchTemplateData")
        return launch_template_data

    def _describe_launch_template_versions_security_groups(self):
        security_groups = {}
        if self.launch_template_data:
            security_group_ids = self.launch_template_data.get("SecurityGroupIds")
            if security_group_ids:
                for sg in security_group_ids:
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

    def _describe_launch_template_versions_iam_roles(self):
        iam_roles = {}
        if self.launch_template_data:
            instance_profile = self.launch_template_data.get("IamInstanceProfile")
            if instance_profile:
                if "Arn" in instance_profile:
                    instance_profile = instance_profile.get("Arn")
                elif "Name" in instance_profile:
                    instance_profile = instance_profile.get("Name")
                arn = IamHelper(
                    self.logger, self.finding, False, self.sess, instance_profile
                ).get_role_from_instance_profile(instance_profile)
                iam_roles[arn] = {}

        return iam_roles

    def describe_auto_scaling_groups(self):
        autoscaling_group = {}
        if self.launch_template:
            response = self.asg_client.describe_auto_scaling_groups()
            if response.get("AutoScalingGroups"):
                for asg in response["AutoScalingGroups"]:
                    try:
                        if (
                            asg["LaunchTemplate"]["LaunchTemplateId"]
                            == self.resource_id
                        ):
                            autoscaling_group[asg["AutoScalingGroupARN"]] = {}
                    except KeyError:
                        # No LaunchTemplate
                        continue
        return autoscaling_group

    # Context Config

    def metadata_options(self):
        metadata_options = False
        if self.launch_template_data:
            metadata_options = self.launch_template_data.get("MetadataOptions")
        return metadata_options

    def associates_public_ip(self):
        associates_public_ip = False
        if self.launch_template_data:
            associates_public_ip = self.launch_template_data.get(
                "AssociatePublicIpAddress"
            )
        return associates_public_ip

    def name(self):
        name = False
        if self.launch_template:
            name = self.launch_template.get("LaunchTemplateName")
        return name

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

    def is_attached(self):
        if self.security_groups:
            return True
        return False

    def public(self):
        if self.associates_public_ip():
            return True
        return False

    def resource_policy(self):
        return None

    def trust_policy(self):
        return None

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
            "name": self.name(),
            "public": self.public(),
            "is_encrypted": self.is_encrypted(),
            "is_attached": self.is_attached(),
            "unrestricted": self.is_unrestricted(),
            "resource_policy": self.resource_policy(),
        }
        return checks
