from lib.context.context import Context
from lib.securityhub import parse_finding


def evaluate_finding(
    logger,
    finding,
    mh_findings,
    mh_findings_not_matched_findings,
    mh_inventory,
    mh_findings_short,
    AwsAccountData,
    mh_role,
    mh_filters_checks,
    mh_filters_tags,
    context_options,
):
    mh_matched = False
    resource_arn, finding_parsed = parse_finding(finding)

    # Fix Region when not in root
    try:
        region = finding["Region"]
    except KeyError:
        region = finding["Resources"][0]["Region"]
        finding["Region"] = region

    # If the resource was already matched or not_matched, we don't run meta* but we show others findings
    if resource_arn in mh_findings:
        mh_matched = True
    elif resource_arn in mh_findings_not_matched_findings:
        mh_matched = False
    elif context_options:
        context = Context(logger, finding, mh_filters_checks, mh_filters_tags, mh_role)
        if "config" in context_options:
            mh_config, mh_checks_matched = context.get_context_config()
        else:
            mh_config = False
            mh_checks_matched = True
        if "tags" in context_options:
            mh_tags, mh_tags_matched = context.get_context_tags()
        else:
            mh_tags = False
            mh_tags_matched = True
        if "cloudtrail" in context_options:
            mh_trails = context.get_context_cloudtrail()
        else:
            mh_trails = False
        if "account" in context_options:
            if finding["AwsAccountId"] not in AwsAccountData:
                mh_account = context.get_context_account()
                AwsAccountData[finding["AwsAccountId"]] = mh_account
            else:
                mh_account = AwsAccountData[finding["AwsAccountId"]]
        else:
            mh_account = False
        # If both checks are True we show the resource
        if mh_tags_matched and mh_checks_matched:
            mh_matched = True
    else:
        # If no metachecks and no metatags, we enforce to True the match so we show the resource:
        mh_matched = True

    # We keep a dict with no matched resources so we don't run MetaChecks again
    if not mh_matched:
        # We add the resource in our output only once:
        if resource_arn not in mh_findings_not_matched_findings:
            mh_findings_not_matched_findings[resource_arn] = {}

    # We show the resouce only if matched MetaChecks and MetaTags (or are disabled)
    if mh_matched:
        # Resource (we add the resource only once, we check if it's already in the list)
        if resource_arn not in mh_findings:
            # Inventory
            mh_inventory.append(resource_arn)
            # Findings
            mh_findings[resource_arn] = {"findings": []}
            mh_findings_short[resource_arn] = {"findings": []}
            # ResourceType
            mh_findings[resource_arn]["ResourceType"] = mh_findings_short[resource_arn][
                "ResourceType"
            ] = finding["Resources"][0]["Type"]
            # Region
            mh_findings[resource_arn]["Region"] = mh_findings_short[resource_arn][
                "Region"
            ] = finding["Region"]
            # AwsAccountId
            mh_findings[resource_arn]["AwsAccountId"] = mh_findings_short[resource_arn][
                "AwsAccountId"
            ] = finding["AwsAccountId"]
            # Add Context
            if mh_config:
                mh_findings[resource_arn].update(mh_config)
                mh_findings_short[resource_arn].update(mh_config)
            else:
                mh_findings[resource_arn]["config"] = False
                mh_findings_short[resource_arn]["config"] = False
            mh_findings[resource_arn]["tags"] = mh_findings_short[resource_arn][
                "tags"
            ] = mh_tags
            mh_findings[resource_arn]["account"] = mh_findings_short[resource_arn][
                "account"
            ] = mh_account
            mh_findings[resource_arn]["cloudtrail"] = mh_findings_short[resource_arn][
                "cloudtrail"
            ] = mh_trails

        # Add Findings
        mh_findings_short[resource_arn]["findings"].append(
            list(finding_parsed.keys())[0]
        )
        mh_findings[resource_arn]["findings"].append(finding_parsed)

    return (
        mh_findings,
        mh_findings_not_matched_findings,
        mh_findings_short,
        mh_inventory,
        AwsAccountData,
    )
