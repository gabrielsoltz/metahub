import boto3
from botocore.exceptions import ClientError, ParamValidationError

from lib.AwsHelpers import assume_role, get_account_id, get_boto3_session


def run_metatags(logger, finding, mh_filters_tags, mh_role, sh_region):
    """
    Executes Tags discover for the AWS Resource Type
    :param logger: logger configuration
    :param finding: AWS Security Hub finding complete
    :param mh_filters: MetaHub filters (--mh-filters-tags)
    :param mh_role: AWS IAM Role to be assumed in the AWS Account (--mh-role)
    :return: mh_tags_values (the MetaTags output as dictionary), mh_tags_matched (a Boolean to confirm if the resource matched the filters)
    """

    AwsAccountId = finding["AwsAccountId"]
    current_account_id = get_account_id(logger)

    # If the resources lives in another account, you need to provide a role for running MetaTags
    if AwsAccountId != current_account_id and not mh_role:
        resource_arn = finding["Resources"][0]["Id"]
        logger.error(
            "Resource %s lives in AWS Account %s, but you are logged in to AWS Account: %s and not mh_role was provided. Ignoring MetaTags...",
            resource_arn,
            AwsAccountId,
            current_account_id,
        )
        if mh_filters_tags:
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

    AWSResourceId = finding["Resources"][0]["Id"]

    if not sess:
        client = boto3.client("resourcegroupstaggingapi", region_name=sh_region)
    else:
        client = sess.client(
            service_name="resourcegroupstaggingapi", region_name=sh_region
        )

    tags = False
    try:
        response = client.get_resources(
            ResourceARNList=[
                AWSResourceId,
            ]
        )
        try:
            tags = response["ResourceTagMappingList"][0]["Tags"]
        except IndexError:
            logger.info("No Tags found for resource: %s", AWSResourceId)
    except ClientError as err:
        logger.warning("Error Fetching Tags %s: %s", AWSResourceId, err)
    except ParamValidationError as err:
        logger.warning("Error Fetching Tags %s: %s", AWSResourceId, err)

    mh_tags_values = {}
    mh_tags_matched = False if mh_filters_tags else True

    # Ignore Case

    if tags:
        for tag in tags:
            mh_tags_values.update({(tag["Key"]): tag["Value"]})

        # Lower Case for better matching:
        mh_tags_values_lower = dict(
            (k.lower(), v.lower()) for k, v in mh_tags_values.items()
        )
        mh_filters_tags_lower = dict(
            (k.lower(), v.lower()) for k, v in mh_filters_tags.items()
        )

        compare = {
            k: mh_tags_values_lower[k]
            for k in mh_tags_values_lower
            if k in mh_filters_tags_lower
            and mh_tags_values_lower[k] == mh_filters_tags_lower[k]
        }
        logger.info(
            "Evaluating MetaTag filter. Expected: "
            + str(mh_filters_tags)
            + " Found: "
            + str(bool(compare))
        )
        if mh_filters_tags and bool(compare):
            mh_tags_matched = True

    return mh_tags_values, mh_tags_matched
