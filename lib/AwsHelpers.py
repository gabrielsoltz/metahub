import boto3
import botocore
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError, ProfileNotFound


def assume_role(logger, aws_account_number, role_name, duration=3600):
    """
    Assumes the provided role in each account and returns the session
    :param aws_account_number: AWS Account Number
    :param role_name: Role to assume in target account
    :return: Assumed Role Credentials
    """
    logger.info("Assuming IAM Role: %s (%s)", role_name, aws_account_number)
    sts_session = boto3.session.Session()
    sts_client = sts_session.client(
        "sts", config=botocore.config.Config(max_pool_connections=100)
    )
    try:
        # Get the current partition
        partition = sts_client.get_caller_identity()["Arn"].split(":")[1]
        response = sts_client.assume_role(
            RoleArn="arn:{}:iam::{}:role/{}".format(
                partition,
                aws_account_number,
                role_name,
            ),
            RoleSessionName="MetaHub",
            DurationSeconds=duration,
        )
    except (ClientError, NoCredentialsError) as e:
        logger.error("Error assuming IAM role: {}".format(e))
        exit(1)
    # Session
    logger.info(
        "Getting session for assumed IAM Role: %s (%s)", role_name, aws_account_number
    )
    Credentials = response["Credentials"]
    access_key = Credentials["AccessKeyId"]
    secret_key = Credentials["SecretAccessKey"]
    session_token = Credentials["SessionToken"]
    try:
        boto3_session = boto3.session.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
        )
    except ClientError as e:
        logger.error("Error getting session for assumed IAM role: {}".format(e))
        exit(1)
    return boto3_session


def get_account_id(logger, sess=None, profile=None):
    account_id = None
    sts = get_boto3_client(logger, "sts", "us-east-1", sess, profile)
    try:
        account_id = sts.get_caller_identity().get("Account")
    except (NoCredentialsError, ClientError, EndpointConnectionError) as e:
        logger.error("Error getting account ID: {}".format(e))
    return account_id


def get_region(logger):
    my_region = None
    try:
        my_session = boto3.session.Session()
        my_region = my_session.region_name
    except (NoCredentialsError, ClientError) as e:
        logger.error("Error getting region: {}".format(e))
    return my_region


def get_available_regions(logger, aws_service):
    try:
        my_session = boto3.session.Session()
        available_regions = my_session.get_available_regions(aws_service)
    except (NoCredentialsError, ClientError) as e:
        logger.error(
            "Error getting available regions for Service {}: {}".format(aws_service, e)
        )
        exit(1)
    return available_regions


def get_account_alias(logger, aws_account_number, role_name=None, profile=None):
    aliases = ""
    local_account = get_account_id(logger, sess=None, profile=profile)
    if aws_account_number != local_account and not role_name:
        return aliases
    if role_name and aws_account_number:
        sess = assume_role(logger, aws_account_number, role_name)
    else:
        sess = None
    iam_client = get_boto3_client(logger, "iam", "us-east-1", sess, profile)
    try:
        aliases = iam_client.list_account_aliases()["AccountAliases"][0]
    except (NoCredentialsError, ClientError, EndpointConnectionError) as e:
        logger.error("Error getting account alias: {}".format(e))
    except IndexError:
        logger.info("No account alias found")
    return aliases


def get_account_alternate_contact(
    logger, aws_account_number, role_name=None, alternate_contact_type="SECURITY"
):
    # https://docs.aws.amazon.com/accounts/latest/reference/using-orgs-trusted-access.html
    # https://aws.amazon.com/blogs/mt/programmatically-managing-alternate-contacts-on-member-accounts-with-aws-organizations/
    alternate_contact = ""
    local_account = get_account_id(logger)
    if aws_account_number != local_account and not role_name:
        return alternate_contact
    if role_name and aws_account_number:
        sess = assume_role(logger, aws_account_number, role_name)
    else:
        sess = None
    account_client = get_boto3_client(logger, "account", "us-east-1", sess)
    try:
        alternate_contact = account_client.get_alternate_contact(
            AccountId=aws_account_number, AlternateContactType=alternate_contact_type
        ).get("AlternateContact")
    except (NoCredentialsError, ClientError, EndpointConnectionError) as e:
        if (
            e.response["Error"]["Code"] == "AccessDeniedException"
            and "The management account can only be managed using the standalone context from the management account."
            in e.response["Error"]["Message"]
        ):
            try:
                alternate_contact = account_client.get_alternate_contact(
                    AlternateContactType=alternate_contact_type
                ).get("AlternateContact")
            except (NoCredentialsError, ClientError, EndpointConnectionError) as e:
                logger.warning(
                    "Error getting alternate contact for account {}: {}".format(
                        aws_account_number, e
                    )
                )
        else:
            logger.warning(
                "Error getting alternate contact for account {}: {}".format(
                    aws_account_number, e
                )
            )
    return alternate_contact


def get_boto3_client(logger, service, region, sess, profile=None):
    if sess:
        return sess.client(service_name=service, region_name=region)
    if profile:
        try:
            return boto3.Session(profile_name=profile).client(
                service_name=service, region_name=region
            )
        except (ProfileNotFound) as e:
            logger.error("Error getting boto3 client using AWS profile (check --sh-profile): {}".format(e))
            exit(1)
    return boto3.client(service, region_name=region)
