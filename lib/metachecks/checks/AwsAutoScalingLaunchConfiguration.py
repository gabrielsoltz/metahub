"""MetaCheck: AwsAutoScalingLaunchConfiguration"""

import boto3
from lib.metachecks.checks.Base import MetaChecksBase
from aws_arn import generate_arn
from lib.metachecks.checks.MetaChecksHelpers import SecurityGroupChecker

class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if metachecks:
            self.region = finding["Region"]
            self.account = finding["AwsAccountId"]
            self.partition = "aws"
            if not sess:
                self.client = boto3.client("autoscaling", region_name=self.region)
            else:
                self.client = sess.client(service_name="autoscaling", region_name=self.region)
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.mh_filters_checks = mh_filters_checks
            self.launch_configuration = self._describe_launch_configuration()
            self.auto_scaling_groups = self._describe_auto_scaling_groups()
            # Security Groups
            self.security_groups = self.describe_security_groups(finding, sess)
    
    # Describe functions

    def _describe_launch_configuration(self):
        response = self.client.describe_launch_configurations(
            LaunchConfigurationNames=[
                self.resource_id,
            ]
        )
        if response["LaunchConfigurations"]:
            return response["LaunchConfigurations"][0]
        return False

    def _describe_auto_scaling_groups(self):
        response = self.client.describe_auto_scaling_groups(
        )
        if response["AutoScalingGroups"]:
            return response["AutoScalingGroups"]
        return False

    # Security Groups

    def describe_security_groups(self, finding, sess):
        sgs = {}
        if self.launch_configuration:
            if self.launch_configuration["SecurityGroups"]:
                for sg in self.launch_configuration["SecurityGroups"]:
                    arn = generate_arn(sg, "ec2", "security_group", self.region, self.account, self.partition)
                    details = SecurityGroupChecker(self.logger, finding, sgs, sess).check_security_group()
                    sgs[arn] = details
        if sgs:
            return sgs
        return False

    # MetaChecks

    def its_associated_with_an_asg(self):
        ASGS = []
        if self.auto_scaling_groups:
            for asg in self.auto_scaling_groups:
                try:
                    if asg["LaunchConfigurationName"] == self.resource_id:
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
                if asg["LaunchConfigurationName"] == self.resource_id:
                    if asg["Instances"]:
                        for instance in asg["Instances"]:
                            ASGSINSTANCES.append(instance["InstanceId"])
        if ASGSINSTANCES:
            return ASGSINSTANCES
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

    def checks(self):
        checks = [
            "is_instance_metadata_v2",
            "is_instance_metadata_hop_limit_1",
            "its_associated_with_an_asg",
            "its_associated_with_asg_instances",
            "its_associated_with_security_groups",
        ]
        return checks