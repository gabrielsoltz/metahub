'''MetaCheck: AwsEc2Instance'''

import boto3
from metachecks.checks.Base import MetaChecksBase

class Metacheck(MetaChecksBase):
    def __init__(self, logger, finding, metachecks, mh_filters_checks, sess):
        self.logger = logger
        if not sess:
            self.client = boto3.client("ec2")
        else:
            self.client = sess.client(service_name="ec2")
        if metachecks:
            self.resource_arn = finding["Resources"][0]["Id"]
            self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
            self.mh_filters_checks = mh_filters_checks
            self.instance = self._describe_instance()
            self.instance_volumes = self._describe_volumes()
            self.instance_security_groups_rules = self._describe_security_group_rules()
            self.instance_profile_roles = self._describe_instance_profile(sess)

    # Describe Functions

    def _describe_instance(self):
        response = self.client.describe_instances(
            InstanceIds=[
                self.resource_id,
            ]
        )
        if response['Reservations']:
            return response['Reservations'][0]['Instances'][0]
        return False

    def _describe_volumes(self):
        BlockDeviceMappings = []
        if self.instance:
            if self.instance['BlockDeviceMappings']:
                for ebs in self.instance['BlockDeviceMappings']:
                    BlockDeviceMappings.append(ebs['Ebs']['VolumeId'])
        if BlockDeviceMappings:
            response = self.client.describe_volumes(
                VolumeIds=BlockDeviceMappings
            )
            return response['Volumes']
        return False

    def _describe_security_group_rules(self):
        SG = []
        if self.instance:
            if self.instance['SecurityGroups']:
                for sg in self.instance['SecurityGroups']:
                    SG.append(sg['GroupId'])
        if SG:
            response = self.client.describe_security_group_rules(
                Filters=[
                    {
                        "Name": "group-id",
                        "Values": SG,
                    },
                ],
            )
            return response["SecurityGroupRules"]
        return False

    def _describe_instance_profile(self, sess):
        IamInstanceProfile = False
        if self.instance:
            try:
                IamInstanceProfile = self.instance["IamInstanceProfile"]['Arn']
            except KeyError:
                IamInstanceProfile = False
        if IamInstanceProfile:
            if not sess:
                client = boto3.client("iam")
            else:
                client = sess.client(service_name="iam")
            response = client.get_instance_profile(
                InstanceProfileName=IamInstanceProfile.split("/")[1]
            )
            return response["InstanceProfile"]
        return False

    # Check Functions

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
            State = self.instance["State"]['Name']
            if State == "running":
                return True
        return False

    def is_attached_to_security_groups(self):
        SG = []
        if self.instance_security_groups_rules:
            for rule in self.instance_security_groups_rules:
                if rule['GroupId'] not in SG:
                    SG.append(rule['GroupId'])
        if SG:
            return SG
        return False

    def is_attached_to_security_group_rules_unrestricted(self):
        UnrestrictedRule = []
        if self.instance_security_groups_rules:
            for rule in self.instance_security_groups_rules:
                if "CidrIpv4" in rule:
                    if "0.0.0.0/0" in rule["CidrIpv4"] and not rule["IsEgress"]:
                        if rule not in UnrestrictedRule:
                            UnrestrictedRule.append(rule)
                if "CidrIpv6" in rule:
                    if "::/0" in rule["CidrIpv6"] and not rule["IsEgress"]:
                        if rule not in UnrestrictedRule:
                            UnrestrictedRule.append(rule)
        if UnrestrictedRule:
            return UnrestrictedRule
        return False

    def it_has_instance_profile(self):
        IamInstanceProfile = False
        if self.instance_profile_roles:
            IamInstanceProfile = self.instance_profile_roles["Arn"]
            return IamInstanceProfile
        return False

    def it_has_instance_profile_roles(self):
        IamInstanceProfileRoles = False
        if self.instance_profile_roles:
            for role in self.instance_profile_roles["Roles"]:
                IamInstanceProfileRoles = role['Arn']
            return IamInstanceProfileRoles
        return False

    def is_instance_metadata_v2(self):      
        HttpTokens = False
        if self.instance:
            try:
                HttpTokens = self.instance["MetadataOptions"]['HttpTokens']
            except KeyError:
                HttpTokens = False
            if HttpTokens == "required":
                return True
        return False

    def is_instance_metadata_hop_limit_1(self):      
        HttpPutResponseHopLimit = False
        if self.instance:
            try:
                HttpPutResponseHopLimit = self.instance["MetadataOptions"]['HttpPutResponseHopLimit']
            except KeyError:
                HttpPutResponseHopLimit = False
            if HttpPutResponseHopLimit == 1:
                return True
        return False

    def it_has_ebs(self):
        EBS = []
        if self.instance_volumes:
            for ebs in self.instance_volumes:
                EBS.append(ebs['VolumeId'])
        if EBS:
            return EBS
        return False

    def it_has_unencrypted_ebs(self):
        EBS = []
        if self.instance_volumes:
            for ebs in self.instance_volumes:
                if not ebs['Encrypted']:
                    EBS.append(ebs['VolumeId'])
        if EBS:
            return EBS
        return False

    def is_public(self):
        if self.it_has_public_ip() and self.is_attached_to_security_group_rules_unrestricted():
            return True
        return False

    def is_encrypted(self):
        if not self.it_has_unencrypted_ebs():
            return True
        return False

    def checks(self):
        checks = [
            "it_has_public_ip",
            "it_has_private_ip",
            "it_has_key",
            "it_has_private_dns",
            "it_has_public_dns",
            "is_running",
            "is_attached_to_security_groups",
            "it_has_instance_profile",
            "it_has_instance_profile_roles",
            "is_instance_metadata_v2",
            "is_instance_metadata_hop_limit_1",
            "it_has_ebs",
            "it_has_unencrypted_ebs",
            "is_attached_to_security_group_rules_unrestricted",
            "is_public",
            "is_encrypted"
        ]
        return checks