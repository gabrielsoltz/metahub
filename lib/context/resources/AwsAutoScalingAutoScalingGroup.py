"""MetaCheck: AwsAutoScalingAutoScalingGroup"""

from aws_arn import generate_arn

from lib.AwsHelpers import get_boto3_client
from lib.context.resources.Base import MetaChecksBase


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
        self.sess = sess
        self.mh_filters_checks = mh_filters_checks
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(
            self.logger, "autoscaling", self.region, self.sess
        )
        # Describe Resource
        self.autoscaling_group = self.describe_auto_scaling_groups()
        if not self.autoscaling_group:
            return False
        self.instances = self._describe_auto_scaling_groups_instances()
        self.launch_templates = self._describe_auto_scaling_groups_launch_template()
        self.launch_configurations = (
            self._describe_auto_scaling_groups_launch_configuration()
        )
        # Drilled MetaChecks

    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_id = (
            finding["Resources"][0]["Id"].split("/")[1]
            if not drilled
            else drilled.split("/")[1]
        )
        self.resource_arn = finding["Resources"][0]["Id"] if not drilled else drilled

    # Describe functions

    def describe_auto_scaling_groups(self):
        response = self.client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[
                self.resource_id,
            ],
        )
        if response["AutoScalingGroups"]:
            return response["AutoScalingGroups"][0]
        return False

    def _describe_auto_scaling_groups_instances(self):
        instances = {}
        if self.autoscaling_group:
            if self.autoscaling_group["Instances"]:
                for instance in self.autoscaling_group["Instances"]:
                    instance_id = instance["InstanceId"]
                    arn = generate_arn(
                        instance_id,
                        "ec2",
                        "instance",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    instances[arn] = {}

        return instances

    def _describe_auto_scaling_groups_launch_template(self):
        if self.autoscaling_group:
            launch_template = self.autoscaling_group.get("LaunchTemplate", False)
            if launch_template:
                launch_template_id = launch_template.get("LaunchTemplateId", False)
                if launch_template_id:
                    arn = generate_arn(
                        launch_template_id,
                        "ec2",
                        "launch_template",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    return {arn: {}}
        return {}

    def _describe_auto_scaling_groups_launch_configuration(self):
        if self.autoscaling_group:
            launch_configuration_name = self.autoscaling_group.get(
                "LaunchConfigurationName", False
            )
            if launch_configuration_name:
                arn = generate_arn(
                    launch_configuration_name,
                    "autoscaling",
                    "launch_configuration",
                    self.region,
                    self.account,
                    self.partition,
                )
                return {arn: {}}
        return {}

    # MetaChecks

    def name(self):
        if self.autoscaling_group:
            return self.autoscaling_group.get("AutoScalingGroupName", False)
        return False

    def associations(self):
        associations = {
            "instances": self.instances,
            "launch_templates": self.launch_templates,
            "launch_configurations": self.launch_configurations,
        }
        return associations

    def checks(self):
        checks = {
            "name": self.name(),
        }
        return checks
