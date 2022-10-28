import metachecks.checks
from AwsHelpers import assume_role, get_boto3_session


def run_metachecks(logger, finding, mh_filters_checks, mh_role):
    """
    Executes MetaChecks for the AWS Resource Type
    :param logger: logger configuration
    :param finding: AWS Security Hub finding complete
    :param mh_filters: MetaHub filters (--mh-filters)
    :param mh_role: AWS IAM Role to be assumed in the AWS Account (--mh-role)
    :return: mh_values (the metachek output as dictionary), mh_matched (a Boolean to confirm if the resource matched the filters)
    """

    meta_checks = True
    meta_tags = False
    mh_filters_tags = False

    # Get a Boto3 Session in the Child Account if mh_role is passed
    AwsAccountId = finding["AwsAccountId"]
    if mh_role:
        sh_role_assumend = assume_role(logger, AwsAccountId, mh_role)
        sess = get_boto3_session(sh_role_assumend)
        logger.info(
            "Assuming IAM Role: %s (%s)",
            mh_role,
            AwsAccountId,
        )
    else:
        sess = None

    AWSResourceType = finding["Resources"][0]["Type"]
    try:
        hndl = getattr(metachecks.checks, AWSResourceType).Metacheck(
            logger, finding, meta_checks, mh_filters_checks, meta_tags, mh_filters_tags, sess
        )
    except AttributeError as err:
        logger.debug("No MetaChecks Handler for AWSResourceType: %s (%s)", AWSResourceType, err)
        if mh_filters_checks:
            return False, False
        return False, True

    logger.info(
        "Running MetaChecks for AWSResourceType: %s (%s)",
        AWSResourceType,
        finding["Resources"][0]["Id"],
    )
    execute = hndl.output_checks()
    logger.info(
        "MetaChecks Result for AWSResourceType: %s (%s): \nExecute: %s",
        AWSResourceType,
        finding["Resources"][0]["Id"],
        execute,
    )

    if execute is not False:
        return execute
    else:
        logger.error(
            "Error running MetaChecks output() for AWSResourceType: %s", AWSResourceType
        )

def list_metachecks(logger):
    """List Meta Checks"""

    meta_checks = False
    mh_filters_checks = False
    meta_tags = False
    mh_filters_tags = False
    sess = False
    finding = False

    import inspect

    for name, obj in inspect.getmembers(metachecks.checks, inspect.ismodule):
        try:
            hndl = getattr(metachecks.checks, name).Metacheck(
                logger, finding, meta_checks, mh_filters_checks, meta_tags, mh_filters_tags, sess
            )
        except AttributeError as err:
            logger.debug("No MetaChecks for AWSResourceType: %s (%s)", name, err)

        execute = hndl.checks()

        if execute is not False:
            print(name + ": " + " ".join(execute))
        else:
            logger.error(
                "Error running MetaCheck checks() for AWSResourceType: %s", name
            )

def run_tags(logger, finding, mh_filters_tags, mh_role):
    """
    Executes Tags discover for the AWS Resource Type
    :param logger: logger configuration
    :param finding: AWS Security Hub finding complete
    :param mh_filters: MetaHub filters (--mh-filters-tags)
    :param mh_role: AWS IAM Role to be assumed in the AWS Account (--mh-role)
    :return: mh_tags_values (the metachek output as dictionary), mh_tags_matched (a Boolean to confirm if the resource matched the filters)
    """

    meta_checks = False
    mh_filters_checks = False
    meta_tags = True

    # Get a Boto3 Session in the Child Account if mh_role is passed
    AwsAccountId = finding["AwsAccountId"]
    if mh_role:
        sh_role_assumend = assume_role(logger, AwsAccountId, mh_role)
        sess = get_boto3_session(sh_role_assumend)
        logger.info(
            "Assuming IAM Role: %s (%s)",
            mh_role,
            AwsAccountId,
        )
    else:
        sess = None

    AWSResourceType = finding["Resources"][0]["Type"]
    try:
        hndl = getattr(metachecks.checks, AWSResourceType).Metacheck(
            logger, finding, meta_checks, mh_filters_checks, meta_tags, mh_filters_tags, sess
        )
    except AttributeError as err:
        logger.debug("No MetaTags Handler for AWSResourceType: %s (%s)", AWSResourceType, err)
        if mh_filters_tags:
            return False, False
        return False, True

    logger.info(
        "Running MetaTags for AWSResourceType: %s (%s)",
        AWSResourceType,
        finding["Resources"][0]["Id"],
    )
    execute = hndl.output_tags()
    logger.info(
        "MetaTags Results for AWSResourceType: %s (%s): \nExecute: %s",
        AWSResourceType,
        finding["Resources"][0]["Id"],
        execute,
    )

    if execute is not False:
        return execute
    else:
        logger.error(
            "Error running MetaTags output() for AWSResourceType: %s", AWSResourceType
        )