"""MetaCheck: AwsAutoScalingAutoScalingGroup"""

from aws_arn import generate_arn

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
            self.client = get_boto3_client(
                self.logger, "autoscaling", self.region, self.sess
            )
            # Describe
            self.auto_scaling_group = self.describe_auto_scaling_groups()
            if not self.auto_scaling_group:
                return False
            self.auto_scaling_instances = self._describe_auto_scaling_groups_instances()
            self.auto_scaling_launch_template = (
                self._describe_auto_scaling_groups_launch_template()
            )
            self.auto_scaling_launch_configuration = (
                self._describe_auto_scaling_groups_launch_configuration()
            )
            # Drilled MetaChecks

    # Describe function

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
        if self.auto_scaling_group:
            if self.auto_scaling_group["Instances"]:
                return self.auto_scaling_group["Instances"]
        return False

    def _describe_auto_scaling_groups_launch_template(self):
        if self.auto_scaling_group:
            return self.auto_scaling_group.get("LaunchTemplate", False)
        return False

    def _describe_auto_scaling_groups_launch_configuration(self):
        if self.auto_scaling_group:
            return self.auto_scaling_group.get("LaunchConfigurationName", False)
        return False

    # MetaChecks

    def its_associated_with_instances(self):
        instances = {}
        if self.auto_scaling_instances:
            for instance in self.auto_scaling_instances:
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

    def its_associated_with_launch_template(self):
        if self.auto_scaling_launch_template:
            return self.auto_scaling_launch_template
        return False

    def its_associated_with_launch_configuration(self):
        if self.auto_scaling_launch_configuration:
            return self.auto_scaling_launch_configuration
        return False

    def checks(self):
        checks = [
            "its_associated_with_instances",
            "its_associated_with_launch_template",
            "its_associated_with_launch_configuration",
        ]
        return checks
