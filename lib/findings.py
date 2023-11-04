from lib.context.context import Context
from lib.metatrails.metatrails import run_metatrails
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
    metachecks,
    mh_filters_checks,
    drill_down,
    metatags,
    mh_filters_tags,
    metatrails,
    metaaccount,
):
    mh_matched = False
    mh_values, mh_tags, mh_trails, mh_account = None, None, None, None
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
    elif metachecks or metatags or metatrails or metaaccount:
        context = Context(logger, finding, mh_filters_checks, mh_filters_tags, mh_role)
        mh_values, mh_checks_matched = context.get_context_config()
        mh_tags, mh_tags_matched = context.get_context_tags()
        # If both checks are True we show the resource
        if mh_tags_matched and mh_checks_matched:
            mh_matched = True
        if finding["AwsAccountId"] not in AwsAccountData:
            mh_account = context.get_context_account()
            AwsAccountData[finding["AwsAccountId"]] = mh_account
        else:
            mh_account = AwsAccountData[finding["AwsAccountId"]]
        # Run MetaTrails
        if metatrails:
            mh_trails = run_metatrails(logger, finding, mh_filters_tags, mh_role)

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
            mh_findings[resource_arn]["context"] = mh_findings_short[resource_arn][
                "context"
            ] = {}
            # MetaChecks
            if metachecks:
                mh_findings[resource_arn]["context"]["config"] = mh_findings_short[
                    resource_arn
                ]["context"]["config"] = mh_values
            # MetaTags
            if metatags:
                mh_findings[resource_arn]["context"]["tags"] = mh_findings_short[
                    resource_arn
                ]["context"]["tags"] = mh_tags
            # MetaAccount
            if metaaccount:
                mh_findings[resource_arn]["context"]["account"] = mh_findings_short[
                    resource_arn
                ]["context"]["account"] = mh_account
            # MetaTrails
            if metatrails:
                mh_findings[resource_arn]["metatrails"] = mh_findings_short[
                    resource_arn
                ]["metatrails"] = mh_trails

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
