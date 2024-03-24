from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from threading import Lock

from alive_progress import alive_bar
from aws_arn import parse_arn

from lib.AwsHelpers import get_account_id
from lib.context.context import Context
from lib.helpers import print_table
from lib.impact.impact import Impact
from lib.securityhub import SecurityHub, parse_finding, parse_region
from lib.statistics import generate_statistics


def generate_findings(
    logger,
    sh_filters,
    sh_region,
    sh_account,
    sh_profile,
    sh_role,
    context,
    mh_role,
    mh_filters_config,
    mh_filters_tags,
    mh_filters_impact,
    inputs,
    asff_findings,
    banners,
):
    mh_findings = {}
    mh_findings_not_matched_findings = {}
    mh_findings_short = {}
    mh_inventory = []
    AwsAccountData = {}

    # We keep a dictionary to avoid processing the same resource more than once
    cached_associated_resources = {}

    # Get current account
    current_account_id = get_account_id(logger)

    findings = []
    if "file-asff" in inputs and asff_findings:
        findings.extend(asff_findings)
        print_table("Input ASFF findings found: ", len(asff_findings), banners=banners)
    if "securityhub" in inputs:
        sh = SecurityHub(logger, sh_region, sh_account, sh_role, sh_profile)
        sh_findings = sh.get_findings(sh_filters)
        findings.extend(sh_findings)
        print_table("Security Hub findings found: ", len(sh_findings), banners=banners)

    resource_locks = {}

    def process_finding(finding):
        # Get the resource_arn from the finding
        resource_arn, finding_parsed = parse_finding(finding)
        # Get the lock for this resource
        lock = resource_locks.get(resource_arn)

        # If the lock does not exist, create it
        if lock is None:
            lock = Lock()
            resource_locks[resource_arn] = lock

        # Acquire the lock for this resource
        with lock:
            # Now process the finding
            return evaluate_finding(
                logger,
                finding,
                mh_findings,
                mh_findings_not_matched_findings,
                mh_inventory,
                mh_findings_short,
                AwsAccountData,
                mh_role,
                mh_filters_config,
                mh_filters_tags,
                context,
                cached_associated_resources,
                current_account_id,
            )

    with alive_bar(title="-> Analyzing findings...", total=len(findings)) as bar:
        try:
            executor = ThreadPoolExecutor()
            # Create future tasks
            futures = [
                executor.submit(process_finding, finding) for finding in findings
            ]

            try:
                # Process futures as they complete
                for future in as_completed(futures):
                    (
                        mh_findings,
                        mh_findings_not_matched_findings,
                        mh_findings_short,
                        mh_inventory,
                        AwsAccountData,
                    ) = future.result()
                    bar()

            except KeyboardInterrupt:
                print(
                    "Keyboard interrupt detected, shutting down all tasks, please wait..."
                )
                for future in futures:
                    future.cancel()  # cancel each future

                # Wait for all futures to be cancelled
                for future in as_completed(futures):
                    try:
                        future.result()  # this will raise a CancelledError if the future was cancelled
                    except CancelledError:
                        pass

        except KeyboardInterrupt:
            print("Keyboard interrupt detected during shutdown. Exiting...")
        finally:
            executor.shutdown(
                wait=False
            )  # shutdown executor without waiting for all threads to finish

    # Generate Impact
    imp = Impact(logger)
    for resource_arn in list(mh_findings):
        impact_checks = imp.generate_impact_checks(
            resource_arn, mh_findings[resource_arn]
        )
        mh_findings[resource_arn]["impact"] = mh_findings_short[resource_arn][
            "impact"
        ] = impact_checks
        # Check if the resources matches the impact filters
        if mh_filters_impact:
            for impact_filter, impact_value in mh_filters_impact.items():
                resource_value = list(impact_checks.get(impact_filter).keys())[0]
                # If it doesn't match, we remove the resource from the findings
                if resource_value != impact_value:
                    del mh_findings[resource_arn]
                    del mh_findings_short[resource_arn]
                    mh_inventory.remove(resource_arn)
                    break

    # Generate Statistics
    mh_statistics = generate_statistics(mh_findings)

    return mh_findings, mh_findings_short, mh_inventory, mh_statistics


def evaluate_finding(
    logger,
    finding,
    mh_findings,
    mh_findings_not_matched_findings,
    mh_inventory,
    mh_findings_short,
    AwsAccountData,
    mh_role,
    mh_filters_config,
    mh_filters_tags,
    context_options,
    cached_associated_resources,
    current_account_id,
):
    mh_matched = False
    resource_arn, finding_parsed = parse_finding(finding)

    # Fixing ASFF: Ensure Region is correctly defined in ASFF
    resource_region = parse_region(resource_arn, finding)
    finding["Region"] = resource_region

    # Fixing ASFF: Ensure ResourceType is correctly defined in ASFF
    original_resourcetype = finding["Resources"][0]["Type"]
    try:
        checked_resourcetype = parse_arn(resource_arn).get("asff_resource")
        if checked_resourcetype == "":
            checked_resourcetype = original_resourcetype
    except KeyError:
        # Invalid resource sub resource type
        checked_resourcetype = original_resourcetype
    except ValueError:
        # Invalid ARN format
        logger.warning(f"Invalid ARN format for {resource_arn}")
        checked_resourcetype = original_resourcetype
    if checked_resourcetype != original_resourcetype:
        logger.warning(
            f"Resource Type is incorrect for {resource_arn}, original: {original_resourcetype}, checked: {checked_resourcetype}. Fixing..."
        )
        finding["Resources"][0]["Type"] = checked_resourcetype

    # If the resource was already matched or not_matched, we don't run meta* but we show others findings
    if resource_arn in mh_findings:
        mh_matched = True
    elif resource_arn in mh_findings_not_matched_findings:
        mh_matched = False
    elif context_options:
        context = Context(
            logger,
            finding,
            mh_filters_config,
            mh_filters_tags,
            mh_role,
            cached_associated_resources,
            current_account_id,
        )
        if "config" in context_options:
            mh_config, mh_checks_matched, all_association = context.get_context_config()
            # Cache the associations for this resource
            cached_associated_resources.update(all_association)
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
            # For fetching Organizations details, we need to be in the master account or a delegated administrator
            if (
                finding["AwsAccountId"] in AwsAccountData
                and AwsAccountData[finding["AwsAccountId"]].get("Organizations")
                and not AwsAccountData[finding["AwsAccountId"]]
                .get("Organizations")
                .get("Details")
            ):
                # It is the master account or a delegated administrator
                if finding["AwsAccountId"] == AwsAccountData[
                    finding["AwsAccountId"]
                ].get("Organizations").get("MasterAccountId") or finding[
                    "AwsAccountId"
                ] in AwsAccountData[
                    finding["AwsAccountId"]
                ].get(
                    "Organizations"
                ).get(
                    "DelegatedAdministrators"
                ):
                    organizations_details = context.get_account_organizations_details()
                    AwsAccountData[finding["AwsAccountId"]]["Organizations"][
                        "Details"
                    ] = organizations_details
                else:
                    AwsAccountData[finding["AwsAccountId"]]["Organizations"][
                        "Details"
                    ] = "n/a"
                mh_account = AwsAccountData[finding["AwsAccountId"]]
        else:
            mh_account = False
        # If both Tags and Config matchs are True we show the resource
        if mh_tags_matched and mh_checks_matched:
            mh_matched = True
    else:
        # If no filters for Config and Tags, we enforce to True the match so we show the resource:
        mh_matched = True

    # We keep a dict with no matched resources so we don't run Context again
    if not mh_matched:
        # We add the resource in our output only once:
        if resource_arn not in mh_findings_not_matched_findings:
            mh_findings_not_matched_findings[resource_arn] = {}

    # We show the resouce only if matched Config and Tags (or are disabled)
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
            if context_options:
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
                mh_findings[resource_arn]["cloudtrail"] = mh_findings_short[
                    resource_arn
                ]["cloudtrail"] = mh_trails

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


def count_mh_findings(mh_findings):
    count = 0
    for resource in mh_findings:
        count += len(mh_findings[resource]["findings"])
    return count
