"""MetaCheck: AwsEc2Instance"""

from aws_arn import generate_arn
from botocore.exceptions import ClientError

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
            self.client = get_boto3_client(self.logger, "ec2", self.region, self.sess)
            # Describe
            self.instance = self.describe_instance()
            if not self.instance: return False
            # Drilled MetaChecks
            self.iam_roles = self.describe_iam_roles()
            self.security_groups = self.describe_security_groups()
            self.autoscaling_group = self._describe_autoscaling_group()
            self.volumes = self.describe_volumes()
            self.vpcs = self._describe_instance_vpc()
            self.subnets = self._describe_instance_subnet()

    # Describe Functions

    def describe_instance(self):
        try:
            response = self.client.describe_instances(
                InstanceIds=[
                    self.resource_id,
                ]
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

    # Drilled MetaChecks
    # For drilled MetaChecks, describe functions must return a dictionary of resources {arn: {}}

    def describe_security_groups(self):
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

    def describe_iam_roles(self):
        iam_roles = {}
        if self.instance:
            instance_profile = self.instance.get("IamInstanceProfile")
            if instance_profile:
                instance_profile_arn = instance_profile.get("Arn")
                arn = IamHelper(
                    self.logger, self.finding, False, self.sess, instance_profile_arn
                ).get_role_from_instance_profile(instance_profile_arn)
                if arn:
                    iam_roles[arn] = {}

        return iam_roles

    def _describe_autoscaling_group(self):
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

    def describe_volumes(self):
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

    def it_has_public_ip(self):
        PublicIp = False
        if self.instance:
            try:
                PublicIp = self.instance["PublicIpAddress"]
            except KeyError:
                PublicIp = False
        return PublicIp

    def it_has_private_ip(self):
        PrivateIp = False
        if self.instance:
            try:
                PrivateIp = self.instance["PrivateIpAddress"]
            except KeyError:
                PrivateIp = False
        return PrivateIp

    def it_has_key(self):
        KeyName = False
        if self.instance:
            try:
                KeyName = self.instance["KeyName"]
            except KeyError:
                KeyName = False
        return KeyName

    def it_has_private_dns(self):
        PrivateDnsName = False
        if self.instance:
            try:
                PrivateDnsName = self.instance["PrivateDnsName"]
            except KeyError:
                PrivateDnsName = False
        if PrivateDnsName:
            return PrivateDnsName
        return False

    def it_has_public_dns(self):
        PublicDnsName = False
        if self.instance:
            try:
                PublicDnsName = self.instance["PublicDnsName"]
            except KeyError:
                PublicDnsName = False
        if PublicDnsName:
            return PublicDnsName
        return False

    def is_running(self):
        State = False
        if self.instance:
            State = self.instance["State"]["Name"]
            if State == "running":
                return True
        return False

    def its_associated_with_security_groups(self):
        if self.security_groups:
            return self.security_groups
        return False

    def it_has_instance_profile(self):
        IamInstanceProfile = False
        if self.instance_profile_roles:
            IamInstanceProfile = self.instance_profile_roles["Arn"]
            return IamInstanceProfile
        return False

    def its_associated_with_iam_roles(self):
        return self.iam_roles

    def is_instance_metadata_v2(self):
        HttpTokens = False
        if self.instance:
            try:
                HttpTokens = self.instance["MetadataOptions"]["HttpTokens"]
            except KeyError:
                HttpTokens = False
            if HttpTokens == "required":
                return True
        return False

    def is_instance_metadata_hop_limit_1(self):
        HttpPutResponseHopLimit = False
        if self.instance:
            try:
                HttpPutResponseHopLimit = self.instance["MetadataOptions"][
                    "HttpPutResponseHopLimit"
                ]
            except KeyError:
                HttpPutResponseHopLimit = False
            if HttpPutResponseHopLimit == 1:
                return True
        return False

    def its_associated_with_ebs(self):
        if self.volumes:
            return self.volumes
        return False

    def its_associated_with_autoscaling_group(self):
        if self.autoscaling_group:
            return self.autoscaling_group
        return False

    def is_public(self):
        public_dict = {}
        if self.it_has_public_ip():
            for sg in self.security_groups:
                if self.security_groups[sg].get("is_ingress_rules_unrestricted"):
                    public_dict[self.it_has_public_ip()] = []
                    for rule in self.security_groups[sg].get(
                        "is_ingress_rules_unrestricted"
                    ):
                        from_port = rule.get("FromPort")
                        to_port = rule.get("ToPort")
                        ip_protocol = rule.get("IpProtocol")
                        public_dict[self.it_has_public_ip()].append(
                            {
                                "from_port": from_port,
                                "to_port": to_port,
                                "ip_protocol": ip_protocol,
                            }
                        )
        if public_dict:
            return public_dict
        return False

    def is_encrypted(self):
        for volume in self.volumes:
            if self.volumes[volume].get("is_encrypted"):
                return True
        return False

    def its_associated_with_vpcs(self):
        if self.vpcs:
            return self.vpcs
        return False

    def its_associated_with_subnets(self):
        if self.subnets:
            return self.subnets
        return False

    def checks(self):
        checks = [
            "it_has_public_ip",
            "it_has_private_ip",
            "it_has_key",
            "it_has_private_dns",
            "it_has_public_dns",
            "its_associated_with_iam_roles",
            "its_associated_with_security_groups",
            "is_instance_metadata_v2",
            "is_instance_metadata_hop_limit_1",
            "its_associated_with_ebs",
            "its_associated_with_autoscaling_group",
            "is_public",
            "is_encrypted",
            "is_running",
            "its_associated_with_vpcs",
            "its_associated_with_subnets",
        ]
        return checks
