from lib.impact.impact import Impact
from lib.metaaccount.metaaccount import run_metaaccount
from lib.metachecks.metachecks import run_metachecks
from lib.metatags.metatags import run_metatags
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
        # Run MetaChecks
        if metachecks:
            mh_values, mh_checks_matched = run_metachecks(
                logger,
                finding,
                mh_filters_checks,
                mh_role,
                drill_down,
            )
        else:
            mh_checks_matched = True
        # Run MetaTags
        if metatags:
            mh_tags, mh_tags_matched = run_metatags(
                logger, finding, mh_filters_tags, mh_role
            )
        else:
            mh_tags_matched = True
        # If both checks are True we show the resource
        if mh_tags_matched and mh_checks_matched:
            mh_matched = True
        # Run MetaTrails
        if metatrails:
            mh_trails = run_metatrails(logger, finding, mh_filters_tags, mh_role)
        # Run MetaAccount, if we already have the information in our dict we don't run it again
        if metaaccount:
            if finding["AwsAccountId"] not in AwsAccountData:
                mh_account = run_metaaccount(finding, mh_role, logger)
                AwsAccountData[finding["AwsAccountId"]] = mh_account
            else:
                mh_account = AwsAccountData[finding["AwsAccountId"]]
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
            # MetaChecks
            if metachecks:
                mh_findings[resource_arn]["metachecks"] = mh_findings_short[
                    resource_arn
                ]["metachecks"] = mh_values
            # MetaTags
            if metatags:
                mh_findings[resource_arn]["metatags"] = mh_findings_short[resource_arn][
                    "metatags"
                ] = mh_tags
            # MetaTrails
            if metatrails:
                mh_findings[resource_arn]["metatrails"] = mh_findings_short[
                    resource_arn
                ]["metatrails"] = mh_trails
            # MetaAccount
            if metaaccount:
                mh_findings[resource_arn]["metaaccount"] = mh_findings_short[
                    resource_arn
                ]["metaaccount"] = mh_account

            # Impact
            impact = Impact().get_impact(mh_findings_short[resource_arn])
            mh_findings[resource_arn]["impact"] = mh_findings_short[resource_arn][
                "impact"
            ] = impact

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
