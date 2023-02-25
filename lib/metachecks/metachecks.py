import lib.metachecks.checks
from lib.AwsHelpers import assume_role, get_boto3_session, get_account_id
from lib.helpers import print_table


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

    AwsAccountId = finding["AwsAccountId"]
    current_account_id = get_account_id(logger)

    AWSResourceType = finding["Resources"][0]["Type"]
    resource_arn = finding["Resources"][0]["Id"]

    # If the resources lives in another account, you need to provide a role for running MetaChecks
    if AwsAccountId != current_account_id and not mh_role:
        logger.error(
            "Resource %s lives in AWS Account %s, but you are logged in to AWS Account: %s and not --mh-assume-role was provided. Ignoring MetaChecks...",
            resource_arn,
            AwsAccountId,
            current_account_id,
        )
        if mh_filters_checks:
            return False, False
        return False, True

    # Get a Boto3 Session in the Child Account if mh_role is passed
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

    try:
        hndl = getattr(lib.metachecks.checks, AWSResourceType).Metacheck(
            logger, finding, meta_checks, mh_filters_checks, sess
        )
    except AttributeError as err:
        logger.info(
            "No MetaChecks Handler for AWSResourceType: %s (%s)", AWSResourceType, err
        )
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
            "Error running MetaChecks output_checks() for AWSResourceType: %s",
            AWSResourceType,
        )


def list_metachecks(logger):
    """List Meta Checks"""

    meta_checks = False
    mh_filters_checks = False
    sess = False
    finding = False

    import inspect

    for name, obj in inspect.getmembers(lib.metachecks.checks, inspect.ismodule):
        if name == "Base":
            continue
        try:
            hndl = getattr(lib.metachecks.checks, name).Metacheck(
                logger, finding, meta_checks, mh_filters_checks, sess
            )
        except AttributeError as err:
            logger.debug("No MetaChecks for AWSResourceType: %s (%s)", name, err)

        execute = hndl.checks()

        if execute is not False:
            print_table(name + ": ", " ".join(execute))
        else:
            logger.error(
                "Error running MetaChecks checks() for AWSResourceType: %s", name
            )
