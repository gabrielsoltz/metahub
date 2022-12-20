import boto3
import botocore
from botocore.exceptions import BotoCoreError, ClientError


def assume_role(logger, aws_account_number, role_name, duration=3600):
    """
    Assumes the provided role in each account and returns Credentials
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :return: Assumed Role Credentials
    """
    sts_session = boto3.session.Session()
    sts_client = sts_session.client(
        "sts", config=botocore.config.Config(max_pool_connections=100)
    )
    # Get the current partition
    partition = sts_client.get_caller_identity()["Arn"].split(":")[1]
    try:
        response = sts_client.assume_role(
            RoleArn="arn:{}:iam::{}:role/{}".format(
                partition,
                aws_account_number,
                role_name,
            ),
            RoleSessionName="MetaHub",
            DurationSeconds=duration,
        )
    except ClientError as e:
        logger.error("Error Assuming Role: {}".format(e))
        exit(1)
    return response["Credentials"]


def get_boto3_session(Credentials):
    access_key = Credentials["AccessKeyId"]
    secret_key = Credentials["SecretAccessKey"]
    session_token = Credentials["SessionToken"]
    boto3_session = boto3.session.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )
    return boto3_session

def get_account_id():
    return boto3.client('sts').get_caller_identity().get('Account')

def get_account_alias(logger, aws_account_number=None, role_name=None):
    if not aws_account_number:
        aliases = boto3.client('iam').list_account_aliases()['AccountAliases']
        if aliases:
            return aliases[0]
        return ""
    elif aws_account_number and role_name:
        sh_role_assumend = assume_role(logger, aws_account_number, role_name)
        sess = get_boto3_session(sh_role_assumend)
        logger.info(
            "Assuming IAM Role: %s (%s)",
            role_name,
            aws_account_number,
        )
        aliases = sess.client(service_name="iam").list_account_aliases()['AccountAliases']
        if aliases:
            return aliases[0]
        return ""
    else:
        return ""
