import boto3
import botocore
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError


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
        aws_session_token=session_token
    )
    return boto3_session

def get_account_id(logger):
    try:
        account_id = boto3.client('sts').get_caller_identity().get('Account')
    except NoCredentialsError as e:
        logger.error("Error Getting Account Id: {}".format(e))
        exit(1)
    return account_id

def get_region(logger):
    my_session = boto3.session.Session()
    my_region = my_session.region_name
    return my_region

def get_available_regions(logger, aws_service):
    my_session = boto3.session.Session()
    available_regions = my_session.get_available_regions(aws_service)
    return available_regions

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

def get_sh_findings_aggregator():
    sh_findings_aggregator = boto3.client('securityhub').list_finding_aggregators()["FindingAggregators"]
    if sh_findings_aggregator:
        sh_findings_aggregator_region = sh_findings_aggregator[0]["FindingAggregatorArn"].split(":")[3]
        return sh_findings_aggregator_region
    return False
