from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client


class IamHelper:
    def __init__(self, logger, finding, role, sess, instance_profile=False):
        self.logger = logger
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.finding = finding
        self.sess = sess
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
        self.iam_client = get_boto3_client(self.logger, "iam", self.region, self.sess)

    def get_role_from_instance_profile(self, instance_profile):
        if "/" in instance_profile:
            instance_profile_name = instance_profile.split("/")[-1]
        else:
            instance_profile_name = instance_profile
        try:
            response = self.iam_client.get_instance_profile(
                InstanceProfileName=instance_profile_name
            )
        except ClientError as e:
            self.logger.error(
                "Error getting role from instance profile %s: %s", instance_profile, e
            )
            return False

        return response["InstanceProfile"]["Roles"][0]["Arn"]
