"""MetaCheck: AwsEc2Instance"""

from aws_arn import generate_arn
from botocore.exceptions import ClientError

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
        self.sess = sess
        self.mh_filters_checks = mh_filters_checks
        self.parse_finding(finding, drilled)
        self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
        # Describe Resource
        self.instance = self.describe_instance()
        if not self.instance:
            return False
        # Drilled Associations
        self.iam_roles = self._describe_instance_iam_roles()
        self.security_groups = self._describe_instance_security_groups()
        self.autoscaling_groups = self._describe_instance_autoscaling_group()
        self.volumes = self._describe_instance_volumes()
        self.subnets = self._describe_instance_subnet()
        self.vpcs = self._describe_instance_vpc()

    # Parse
    def parse_finding(self, finding, drilled):
        self.finding = finding
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split("/")[1]

    # Describe Functions

    def describe_instance(self):
        try:
            response = self.client.describe_instances(
                InstanceIds=[
                    self.resource_id,
                ],
                Filters=[
                    {
                        "Name": "instance-state-name",
                        "Values": [
                            "pending",
                            "running",
                            "shutting-down",
                            "stopping",
                            "stopped",
                        ],
                    }
                ],
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                self.logger.info(
                    "Failed to describe_instance: {}, {}".format(self.resource_id, err)
                )
                return False
            else:
                self.logger.error(
                    "Failed to describe_instance: {}, {}".format(self.resource_id, err)
                )
                return False
        if response["Reservations"]:
            return response["Reservations"][0]["Instances"][0]
        return False

    def _describe_instance_iam_roles(self):
        iam_roles = {}
        if self.instance:
            profile = self.instance.get("IamInstanceProfile")
            if profile:
                profile_arn = profile.get("Arn")
                arn = IamHelper(
                    self.logger, self.finding, False, self.sess, profile_arn
                ).get_role_from_instance_profile(profile_arn)
                if arn:
                    iam_roles[arn] = {}

        return iam_roles

    def _describe_instance_security_groups(self):
        security_groups = {}
        if self.instance:
            if self.instance["SecurityGroups"]:
                for sg in self.instance["SecurityGroups"]:
                    arn = generate_arn(
                        sg["GroupId"],
                        "ec2",
                        "security_group",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    security_groups[arn] = {}

        return security_groups

    def _describe_instance_autoscaling_group(self):
        autoscaling_group = {}
        if self.instance:
            tags = self.instance.get("Tags")
            for tag in tags:
                if tag.get("Key") == "aws:autoscaling:groupName":
                    asg_name = tag.get("Value")
                    arn = generate_arn(
                        asg_name,
                        "autoscaling",
                        "auto_scaling_group",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    autoscaling_group[arn] = {}

        return autoscaling_group

    def _describe_instance_volumes(self):
        volumes = {}
        if self.instance:
            if self.instance["BlockDeviceMappings"]:
                for ebs in self.instance["BlockDeviceMappings"]:
                    arn = generate_arn(
                        ebs["Ebs"]["VolumeId"],
                        "ec2",
                        "volume",
                        self.region,
                        self.account,
                        self.partition,
                    )
                    volumes[arn] = {}

        return volumes

    def _describe_instance_subnet(self):
        subnet = {}
        if self.instance:
            if self.instance.get("SubnetId"):
                arn = generate_arn(
                    self.instance["SubnetId"],
                    "ec2",
                    "subnet",
                    self.region,
                    self.account,
                    self.partition,
                )
                subnet[arn] = {}
        return subnet

    def _describe_instance_vpc(self):
        vpc = {}
        if self.instance:
            if self.instance.get("VpcId"):
                arn = generate_arn(
                    self.instance["VpcId"],
                    "ec2",
                    "vpc",
                    self.region,
                    self.account,
                    self.partition,
                )
                vpc[arn] = {}
        return vpc

    # MetaChecks

    def public_ip(self):
        public_ip = False
        if self.instance:
            public_ip = self.instance.get("PublicIpAddress")
        return public_ip

    def private_ip(self):
        private_ip = False
        if self.instance:
            private_ip = self.instance.get("PrivateIpAddress")
        return private_ip

    def key(self):
        key = False
        if self.instance:
            key = self.instance.get("KeyName")
        return key

    def private_dns(self):
        private_dns = False
        if self.instance:
            private_dns = self.instance.get("PrivateDnsName")
        return private_dns

    def public_dns(self):
        public_dns = False
        if self.instance:
            public_dns = self.instance.get("PublicDnsName")
        return public_dns

    def iam_profile(self):
        profile_arn = False
        if self.instance:
            profile = self.instance.get("IamInstanceProfile")
            if profile:
                profile_arn = profile.get("Arn")
        return profile_arn

    def metadata_options(self):
        metadata_options = False
        if self.instance:
            metadata_options = self.instance.get("MetadataOptions")
        return metadata_options

    def is_running(self):
        State = False
        if self.instance:
            State = self.instance["State"]["Name"]
            if State == "running":
                return True
        return False

    def is_encrypted(self):
        for volume in self.volumes:
            if self.volumes[volume].get("is_encrypted"):
                return True
        return False

    def is_unrestricted(self):
        if self.iam_roles:
            for role in self.iam_roles:
                if self.iam_roles[role].get("is_unrestricted"):
                    return self.iam_roles[role].get("is_unrestricted")
        return False

    def public(self):
        if self.public_ip():
            return True
        return False

    def associations(self):
        associations = {
            "security_groups": self.security_groups,
            "iam_roles": self.iam_roles,
            "volumes": self.volumes,
            "autoscaling_groups": self.autoscaling_groups,
            "vpcs": self.vpcs,
            "subnets": self.subnets,
        }
        return associations

    def checks(self):
        checks = {
            "public_ip": self.public_ip(),
            "private_ip": self.private_ip(),
            "key": self.key(),
            "private_dns": self.private_dns(),
            "public_dns": self.public_dns(),
            "metadata_options": self.metadata_options(),
            "iam_profile": self.iam_profile(),
            "is_running": self.is_running(),
            "public": self.public(),
            "is_encrypted": self.is_encrypted(),
            "is_unrestricted": self.is_unrestricted(),
        }
        return checks
