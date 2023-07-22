from botocore.exceptions import ClientError, ParamValidationError

from lib.AwsHelpers import assume_role, get_account_id, get_boto3_client
from lib.config.resources import MetaHubResourcesConfig


def run_metatrails(logger, finding, mh_filters_trails, mh_role):
    """
    Executes Trails discover for the AWS Resource Type
    """

    resource_account_id = finding["AwsAccountId"]
    resource_region = finding["Region"]
    resource_id = finding["Resources"][0]["Id"]
    resource_type = finding["Resources"][0]["Type"]
    current_account_id = get_account_id(logger)

    logger.info(
        "Running MetaTrails for ResourceType: %s (%s)",
        resource_type,
        finding["Resources"][0]["Id"],
    )

    # If the resources lives in another account, you need to provide a role for running MetaTrails
    if resource_account_id != current_account_id and not mh_role:
        resource_arn = finding["Resources"][0]["Id"]
        logger.warning(
            "Resource %s lives in AWS Account %s, but you are logged in to AWS Account %s and not --mh-assume-role was provided. Ignoring MetaTrails...",
            resource_arn,
            resource_account_id,
            current_account_id,
        )
        if mh_filters_trails:
            return False, False
        return False, True

    # Get a Boto3 Session in the Child Account if mh_role is passed
    if mh_role:
        sess = assume_role(logger, resource_account_id, mh_role)
    else:
        sess = None

    client = get_boto3_client(logger, "cloudtrail", resource_region, sess)

    trails = {}
    try:
        paginator = client.get_paginator("lookup_events")

        try:
            parsing_char = MetaHubResourcesConfig[resource_type]["ResourceName"][
                "parsing_char"
            ]
            parsing_pos = MetaHubResourcesConfig[resource_type]["ResourceName"][
                "parsing_pos"
            ]
            if parsing_char is not None:
                ResourceName = finding["Resources"][0]["Id"].split(parsing_char)[
                    parsing_pos
                ]
            else:
                ResourceName = finding["Resources"][0]["Id"]
            event_names = MetaHubResourcesConfig[resource_type]["metatrails_events"]
        except KeyError:
            # No Config Defined
            return False

        page_iterator = paginator.paginate(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": ResourceName}
            ]
        )

        if event_names:
            for page in page_iterator:
                for event in page["Events"]:
                    for event_name in event_names:
                        if event["EventName"] == event_name:
                            trails[event["EventName"]] = {
                                "Username": event["Username"],
                                "EventTime": str(event["EventTime"]),
                                "EventId": event["EventId"],
                            }

    except (ClientError, ParamValidationError, Exception) as err:
        logger.warning("Error Fetching Trails %s: %s", resource_id, err)

    if trails:
        mh_trails_values = trails
        return mh_trails_values
    else:
        return False
