import boto3
from botocore.exceptions import BotoCoreError, ClientError, ParamValidationError
from datetime import datetime

from lib.AwsHelpers import assume_role, get_boto3_session, get_account_id
from lib.config.resources import MetaHubResourcesConfig

def run_metatrails(logger, finding, mh_filters_trails, mh_role, sh_region):
    """
    Executes Trails discover for the AWS Resource Type
    """

    AwsAccountId = finding["AwsAccountId"]
    current_account_id = get_account_id(logger)

    # If the resources lives in another account, you need to provide a role for running MetaTrails
    if AwsAccountId != current_account_id and not mh_role:
        resource_arn = finding["Resources"][0]["Id"]
        logger.error(
            "Resource %s lives in AWS Account %s, but you are logged in to AWS Account: %s and not mh_role was provided. Ignoring MetaTrails...",
            resource_arn,
            AwsAccountId,
            current_account_id,
        )
        if mh_filters_trails:
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
    AWSResourceType = finding["Resources"][0]["Type"]

    if not sess:
        client = boto3.client("cloudtrail", region_name=sh_region)
    else:
        client = sess.client(
            service_name="cloudtrail", region_name=sh_region
        )

    trails = {}
    try:
        paginator = client.get_paginator('lookup_events')

        try:
            ResourceName = finding["Resources"][0]["Id"].split(MetaHubResourcesConfig[AWSResourceType]["ResourceName"]["parsing_char"])[MetaHubResourcesConfig[AWSResourceType]["ResourceName"]["parsing_pos"]]
            event_names = MetaHubResourcesConfig[AWSResourceType]["metatrails_events"]
        except KeyError:
            # No Config Defined
            return False

        page_iterator = paginator.paginate(LookupAttributes=[{'AttributeKey': 'ResourceName', 'AttributeValue': ResourceName}])

        if event_names:
            for page in page_iterator:
                for event in page['Events']:
                    for event_name in event_names:
                        if event["EventName"] == event_name:
                            trails[event["EventName"]] = {"Username": event["Username"], "EventTime": str(event["EventTime"])}

    except ClientError as err:
        logger.warning("Error Fetching Trails %s: %s", AWSResourceId, err)
    except ParamValidationError as err:
        logger.warning("Error Fetching Trails %s: %s", AWSResourceId, err)

    if trails:
        mh_trails_values = trails
        return mh_trails_values
    else:
        return False
