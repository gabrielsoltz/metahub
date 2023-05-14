import boto3
import botocore
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError


def assume_role(logger, aws_account_number, role_name, duration=3600):
    """
    Assumes the provided role in each account and returns Credentials
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
    except ClientError as e:
        logger.error("Error assuming IAM role: {}".format(e))
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


def get_account_id(logger):
    account_id = None
    try:
        account_id = boto3.client("sts").get_caller_identity().get("Account")
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


def get_account_alias(logger, aws_account_number=None, role_name=None):
    aliases = None
    if role_name and aws_account_number:
        sh_role_assumend = assume_role(logger, aws_account_number, role_name)
        sess = get_boto3_session(sh_role_assumend)
        iam_client = sess.client(service_name="iam")
    else:
        iam_client = boto3.client("iam")

    try:
        aliases = iam_client.list_account_aliases()["AccountAliases"]
    except (NoCredentialsError, ClientError, EndpointConnectionError) as e:
        logger.error("Error getting account alias: {}".format(e))
        aliases = None

    if aliases:
        return aliases[0]
    return ""


def get_account_alternate_contact(
    logger, aws_account_number=None, role_name=None, alternate_contact_type="SECURITY"
):
    # https://docs.aws.amazon.com/accounts/latest/reference/using-orgs-trusted-access.html
    # https://aws.amazon.com/blogs/mt/programmatically-managing-alternate-contacts-on-member-accounts-with-aws-organizations/

    alternate_contact = ""

    if role_name and aws_account_number:
        sh_role_assumend = assume_role(logger, aws_account_number, role_name)
        sess = get_boto3_session(sh_role_assumend)
        account_client = sess.client(service_name="account")
    else:
        account_client = boto3.client("account")

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
                logger.error(
                    "Error getting alternate contact for account {}: {}".format(
                        aws_account_number, e
                    )
                )
        else:
            logger.error(
                "Error getting alternate contact for account {}: {}".format(
                    aws_account_number, e
                )
            )

    if alternate_contact:
        return alternate_contact
    return ""


def get_sh_findings_aggregator(logger, region):
    try:
        sh_findings_aggregator = boto3.client(
            "securityhub", region_name=region
        ).list_finding_aggregators()["FindingAggregators"]
    except (EndpointConnectionError, Exception) as e:
        logger.error("Error getting securityhub aggregators: {}".format(e))
        return False
    if sh_findings_aggregator:
        sh_findings_aggregator_region = sh_findings_aggregator[0][
            "FindingAggregatorArn"
        ].split(":")[3]
        return sh_findings_aggregator_region
    return False


def get_boto3_client(logger, service, region, sess):
    if not sess:
        return boto3.client(service, region_name=region)
    else:
        return sess.client(service_name=service, region_name=region)
