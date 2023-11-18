from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed
from threading import Lock

from alive_progress import alive_bar

from lib.context.context import Context
from lib.helpers import confirm_choice, print_table
from lib.impact.impact import Impact
from lib.securityhub import SecurityHub, parse_finding
from lib.statistics import generate_statistics


def update_findings(
    logger,
    mh_findings,
    update,
    sh_account,
    sh_role,
    sh_region,
    update_filters,
    sh_profile,
    actions_confirmation,
):
    sh = SecurityHub(logger, sh_region, sh_account, sh_role, sh_profile)
    if confirm_choice(
        "Are you sure you want to update all findings?", actions_confirmation
    ):
        update_multiple = sh.update_findings_workflow(mh_findings, update_filters)
        update_multiple_ProcessedFinding = []
        update_multiple_UnprocessedFindings = []
        for update in update_multiple:
            for ProcessedFinding in update["ProcessedFindings"]:
                logger.info("Updated Finding : " + ProcessedFinding["Id"])
                update_multiple_ProcessedFinding.append(ProcessedFinding)
            for UnprocessedFinding in update["UnprocessedFindings"]:
                logger.error(
                    "Error Updating Finding: "
                    + UnprocessedFinding["FindingIdentifier"]["Id"]
                    + " Error: "
                    + UnprocessedFinding["ErrorMessage"]
                )
                update_multiple_UnprocessedFindings.append(UnprocessedFinding)
        return update_multiple_ProcessedFinding, update_multiple_UnprocessedFindings
    return [], []


def enrich_findings(
    logger,
    mh_findings,
    sh_account,
    sh_role,
    sh_region,
    sh_profile,
    actions_confirmation,
):
    sh = SecurityHub(logger, sh_region, sh_account, sh_role, sh_profile)
    if confirm_choice(
        "Are you sure you want to enrich all findings?", actions_confirmation
    ):
        update_multiple = sh.update_findings_meta(mh_findings)
        update_multiple_ProcessedFinding = []
        update_multiple_UnprocessedFindings = []
        for update in update_multiple:
            for ProcessedFinding in update["ProcessedFindings"]:
                logger.info("Updated Finding : " + ProcessedFinding["Id"])
                update_multiple_ProcessedFinding.append(ProcessedFinding)
            for UnprocessedFinding in update["UnprocessedFindings"]:
                logger.error(
                    "Error Updating Finding: "
                    + UnprocessedFinding["FindingIdentifier"]["Id"]
                    + " Error: "
                    + UnprocessedFinding["ErrorMessage"]
                )
                update_multiple_UnprocessedFindings.append(UnprocessedFinding)
        return update_multiple_ProcessedFinding, update_multiple_UnprocessedFindings
    return [], []


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
    inputs,
    asff_findings,
    banners,
):
    mh_findings = {}
    mh_findings_not_matched_findings = {}
    mh_findings_short = {}
    mh_inventory = []
    AwsAccountData = {}

    # We keep a dictionary to avoid to process the same resource more than once
    cached_associated_resources = {}

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
        # To Do: If more than one finding for the same account, account_context could execute more than once for the same account
        # Split the findings by account and execute the account_context only once per account
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
            )

    with alive_bar(title="-> Analizing findings...", total=len(findings)) as bar:
        try:
            executor = (
                ThreadPoolExecutor()
            )  # create executor outside of context manager
            # Create future tasks
            futures = {
                executor.submit(process_finding, finding) for finding in findings
            }

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

    mh_statistics = generate_statistics(mh_findings)

    # Add Impact
    imp = Impact(logger)
    for resource_arn, resource_values in mh_findings.items():
        impact_checks = imp.generate_impact_checks(resource_arn, resource_values)
        mh_findings[resource_arn]["impact"] = mh_findings_short[resource_arn][
            "impact"
        ] = impact_checks
    for resource_arn, resource_values in mh_findings.items():
        impact_scoring = imp.generate_impact_scoring(resource_arn, resource_values)
        mh_findings[resource_arn]["impact"]["score"] = mh_findings_short[resource_arn][
            "impact"
        ]["score"] = impact_scoring
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
        context = Context(
            logger,
            finding,
            mh_filters_config,
            mh_filters_tags,
            mh_role,
            cached_associated_resources,
        )
        if "config" in context_options:
            mh_config, mh_checks_matched = context.get_context_config()
            # Get and Cache the associations for this resource
            if mh_config:
                cached_associated_resources.update(get_associations(mh_config))
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


# From each resource, get the associations, so we can cache them and avoid to get them again
def get_associations(resource):
    associations_all = {}

    def get_associations_recursively(dictionary, parent_key=""):
        for key, value in dictionary.items():
            if isinstance(value, dict):
                if key == "associations":
                    for atype, associations in value.items():
                        if isinstance(associations, dict):
                            for association, association_values in associations.items():
                                if association_values:
                                    associations_all[association] = association_values
                get_associations_recursively(
                    value, f"{parent_key}.{key}" if parent_key else key
                )

    get_associations_recursively(resource)
    return associations_all
