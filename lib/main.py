import json
from sys import argv, exit
from time import strftime

from alive_progress import alive_bar

from lib.AwsHelpers import (
    get_account_alias,
    get_account_alternate_contact,
    get_account_id,
    get_region,
    get_sh_findings_aggregator,
)
from lib.helpers import (
    confirm_choice,
    get_logger,
    get_parser,
    print_banner,
    print_table,
    print_title_line,
    test_python_version,
)
from lib.securityhub import SecurityHub

OUTPUT_DIR = "outputs/"
TIMESTRF = strftime("%Y%m%d-%H%M%S")


def generate_statistics(mh_findings):
    def statistics_root_level(mh_findings):
        root_level_statistics = {
            "ResourceId": {},
            "ResourceType": {},
            "Region": {},
            "AwsAccountId": {},
            "Title": {},
            "SeverityLabel": {},
            "RecordState": {},
            "ProductArn": {},
            "Workflow": {},
            "Compliance": {},
        }
        for resource_arn in mh_findings:
            if resource_arn not in root_level_statistics:
                root_level_statistics["ResourceId"][resource_arn] = 0
            root_level_statistics["ResourceId"][resource_arn] += 1
            for key, value in mh_findings[resource_arn].items():
                if key in ("ResourceType", "Region", "AwsAccountId"):
                    if value not in root_level_statistics[key]:
                        root_level_statistics[key][value] = 0
                    root_level_statistics[key][value] += 1
                if key == "findings":
                    for finding in value:
                        for finding_key, finding_value in finding.items():
                            if finding_key not in root_level_statistics["Title"]:
                                root_level_statistics["Title"][finding_key] = 0
                            root_level_statistics["Title"][finding_key] += 1
                            for v in finding_value:
                                if v in ("Id", "StandardsControlArn"):
                                    continue
                                if v == "Workflow" or v == "Compliance":
                                    try:
                                        if (
                                            finding_value[v]["Status"]
                                            not in root_level_statistics[v]
                                        ):
                                            root_level_statistics[v][
                                                finding_value[v]["Status"]
                                            ] = 0
                                        root_level_statistics[v][
                                            finding_value[v]["Status"]
                                        ] += 1
                                    except TypeError:
                                        continue
                                else:
                                    if finding_value[v] not in root_level_statistics[v]:
                                        root_level_statistics[v][finding_value[v]] = 0
                                    root_level_statistics[v][finding_value[v]] += 1

        return root_level_statistics

    def statistics_metatags(mh_findings_short):
        metatags_statistics = {}
        for d in mh_findings_short:
            if "metatags" in mh_findings_short[d]:
                if mh_findings_short[d]["metatags"]:
                    for tag, value in mh_findings_short[d]["metatags"].items():
                        if tag not in metatags_statistics:
                            metatags_statistics[tag] = {}
                        if value not in metatags_statistics[tag]:
                            metatags_statistics[tag][value] = 1
                        else:
                            metatags_statistics[tag][value] += 1
        return metatags_statistics

    def statistics_metachecks(mh_findings_short):
        metachecks_statistics = {}
        for d in mh_findings_short:
            if "metachecks" in mh_findings_short[d]:
                if mh_findings_short[d]["metachecks"]:
                    for check, value in mh_findings_short[d]["metachecks"].items():
                        if check not in metachecks_statistics:
                            metachecks_statistics[check] = {False: 0, True: 0}
                        if bool(mh_findings_short[d]["metachecks"][check]):
                            metachecks_statistics[check][True] += 1
                        else:
                            metachecks_statistics[check][False] += 1
        return metachecks_statistics

    def statistics_metaaccount(mh_findings_short):
        metaaccount_statistics = {}
        for d in mh_findings_short:
            if "metaaccount" in mh_findings_short[d]:
                if mh_findings_short[d]["metaaccount"]:
                    for tag, value in mh_findings_short[d]["metaaccount"].items():
                        if tag == "AlternateContact":
                            continue
                        if tag not in metaaccount_statistics:
                            metaaccount_statistics[tag] = {}
                        if value not in metaaccount_statistics[tag]:
                            metaaccount_statistics[tag][value] = 1
                        else:
                            metaaccount_statistics[tag][value] += 1
        return metaaccount_statistics

    mh_statistics = statistics_root_level(mh_findings)
    mh_statistics["metatags"] = statistics_metatags(mh_findings)
    mh_statistics["metachecks"] = statistics_metachecks(mh_findings)
    mh_statistics["metaaccount"] = statistics_metaaccount(mh_findings)

    # Sort Statistics
    for key_to_sort in mh_statistics:
        if key_to_sort not in ("metatags", "metachecks", "metaaccount"):
            mh_statistics[key_to_sort] = dict(
                sorted(
                    mh_statistics[key_to_sort].items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
            )

    return mh_statistics


def generate_findings(
    logger,
    sh_filters,
    metachecks,
    mh_filters_checks,
    metatags,
    mh_filters_tags,
    sh_account,
    sh_role,
    mh_role,
    sh_region,
    inputs,
    asff_findings,
    metatrails,
    banners,
    drill_down,
):
    mh_findings = {}
    mh_findings_not_matched_findings = {}
    mh_findings_short = {}
    mh_inventory = []
    AwsAccountData = {}

    sh = SecurityHub(logger, sh_region, sh_account, sh_role)

    findings = []
    if "file-asff" in inputs and asff_findings:
        findings.extend(asff_findings)
        print_table("Input ASFF findings found: ", len(asff_findings), banners=banners)
    if "securityhub" in inputs:
        sh_findings = sh.get_findings(sh_filters)
        findings.extend(sh_findings)
        print_table("Security Hub findings found: ", len(sh_findings), banners=banners)

    with alive_bar(total=len(findings)) as bar:
        for finding in findings:
            bar.title = "-> Analyzing findings..."

            mh_matched = False
            resource_arn, finding_parsed = sh.parse_finding(finding)

            # Fix Region when not in root
            try:
                region = finding["Region"]
            except KeyError:
                region = finding["Resources"][0]["Region"]
                finding["Region"] = region

            # MetaChecks and MetaTags:
            if metachecks or metatags or metatrails:
                from lib.metachecks.metachecks import run_metachecks
                from lib.metatags.metatags import run_metatags
                from lib.metatrails.metatrails import run_metatrails

                # If the resource was already matched, we don't run metachecks or metatags again but we show others findings
                if resource_arn in mh_findings:
                    mh_matched = True
                elif resource_arn in mh_findings_not_matched_findings:
                    mh_matched = False
                else:
                    if metachecks:
                        # We run metachecks only once, if the resource is in mh_findings or mh_findings_not_matched_findings, means it was already evaluated:
                        if (
                            resource_arn not in mh_findings
                            and resource_arn not in mh_findings_not_matched_findings
                        ):
                            mh_values, mh_checks_matched = run_metachecks(
                                logger,
                                finding,
                                mh_filters_checks,
                                mh_role,
                                drill_down,
                            )
                    else:
                        mh_checks_matched = True
                    if metatags:
                        # We run metatags only once:
                        if (
                            resource_arn not in mh_findings
                            and resource_arn not in mh_findings_not_matched_findings
                        ):
                            mh_tags, mh_tags_matched = run_metatags(
                                logger, finding, mh_filters_tags, mh_role
                            )
                    else:
                        mh_tags_matched = True
                    # If both checks are True we show the resource
                    if mh_tags_matched and mh_checks_matched:
                        mh_matched = True

                    # MetaTrails runs without filters, for now?
                    if metatrails:
                        # We run metatrails only once:
                        if (
                            resource_arn not in mh_findings
                            and resource_arn not in mh_findings_not_matched_findings
                        ):
                            mh_trails = run_metatrails(
                                logger, finding, mh_filters_tags, mh_role
                            )
            else:
                # If no metachecks and no metatags, we enforce to True the match so we show the resource:
                mh_matched = True

            # We keep a dict with no matched resources so we don't run MetaChecks again
            if not mh_matched:
                # We add the resource in our output only once:
                if resource_arn not in mh_findings_not_matched_findings:
                    mh_findings_not_matched_findings[resource_arn] = {}

            # We show the resouce only if matched MetaChecks (or Metachecks are disabled)
            if mh_matched:

                # Get MetaAccount Data (We save the data in a dict to avoid calling the API for each finding)
                if finding["AwsAccountId"] not in AwsAccountData:
                    AwsAccountAlias = get_account_alias(
                        logger, finding["AwsAccountId"], mh_role
                    )
                    AwsAccountAlternateContact = get_account_alternate_contact(
                        logger, finding["AwsAccountId"], mh_role
                    )
                    AwsAccountData[finding["AwsAccountId"]] = {
                        "Alias": AwsAccountAlias,
                        "AlternateContact": AwsAccountAlternateContact,
                    }
                finding["AwsAccountData"] = AwsAccountData[finding["AwsAccountId"]]

                # Resource (we add the resource only once, we check if it's already in the list)
                if resource_arn not in mh_findings:
                    # Inventory
                    mh_inventory.append(resource_arn)
                    # Findings
                    mh_findings[resource_arn] = {"findings": []}
                    mh_findings_short[resource_arn] = {"findings": []}
                    # ResourceType
                    mh_findings[resource_arn]["ResourceType"] = mh_findings_short[
                        resource_arn
                    ]["ResourceType"] = finding["Resources"][0]["Type"]
                    # Region
                    mh_findings[resource_arn]["Region"] = mh_findings_short[
                        resource_arn
                    ]["Region"] = finding["Region"]
                    # AwsAccountId
                    mh_findings[resource_arn]["AwsAccountId"] = mh_findings_short[
                        resource_arn
                    ]["AwsAccountId"] = finding["AwsAccountId"]
                    # MetaAccount
                    mh_findings[resource_arn]["metaaccount"] = mh_findings_short[
                        resource_arn
                    ]["metaaccount"] = finding["AwsAccountData"]
                    # MetaChecks
                    if metachecks:
                        mh_findings[resource_arn]["metachecks"] = mh_findings_short[
                            resource_arn
                        ]["metachecks"] = mh_values
                    # MetaTags
                    if metatags:
                        mh_findings[resource_arn]["metatags"] = mh_findings_short[
                            resource_arn
                        ]["metatags"] = mh_tags
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

            bar()
        bar.title = "-> Completed"

    mh_statistics = generate_statistics(mh_findings)

    return mh_findings, mh_findings_short, mh_inventory, mh_statistics


def update_findings(logger, mh_findings, update, sh_account, sh_role, sh_region):
    UpdateFilters = {}
    IsNnoteProvided = False
    IsAllowedKeyProvided = False
    for key, value in update.items():
        if key in ("Workflow", "Note"):
            if key == "Workflow":
                WorkflowValues = ("NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED")
                if value not in WorkflowValues:
                    logger.error("Workflow values: " + str(WorkflowValues))
                    exit(1)
                Workflow = {"Workflow": {"Status": value}}
                UpdateFilters.update(Workflow)
                IsAllowedKeyProvided = True
            if key == "Note":
                Note = {"Note": {"Text": value, "UpdatedBy": "MetaHub"}}
                UpdateFilters.update(Note)
                IsNnoteProvided = True
            continue
        logger.error(
            "Unsuported update finding key: " + str(key) + " - Supported Keys: Workflow"
        )
        exit(1)
    if not IsAllowedKeyProvided:
        logger.error(
            'Missing Key to Update in update findings command. Please add Key="This is a value"'
        )
        exit(1)
    if not IsNnoteProvided:
        logger.error(
            'Missing Note in update findings command. Please add Note="This is an example Note"'
        )
        exit(1)
    # Run Update
    sh = SecurityHub(logger, sh_region, sh_account, sh_role)
    if confirm_choice("Are you sure you want to update all findings?"):
        update_multiple = sh.update_findings_workflow(mh_findings, UpdateFilters)
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


def enrich_findings(logger, mh_findings, sh_account, sh_role, sh_region):
    sh = SecurityHub(logger, sh_region, sh_account, sh_role)
    if confirm_choice("Are you sure you want to enrich all findings?"):
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


def count_mh_findings(mh_findings):
    count = 0
    for resource in mh_findings:
        count += len(mh_findings[resource]["findings"])
    return count


def set_sh_filters(sh_filters):
    """Return filters for AWS Security Hub get_findings Call"""
    filters = {}
    for key, values in sh_filters.items():
        if key != "self" and values is not None:
            filters[key] = []
            for value in values:
                value_to_append = {"Comparison": "EQUALS", "Value": value}
                filters[key].append(value_to_append)
    return filters


def validate_arguments(args, logger):

    # Validate no filters when using file-asff only
    if "file-asff" in args.inputs and "securityhub" not in args.inputs:
        if args.sh_template or args.sh_filters:
            logger.error(
                "--sh-filters not supported for file-asff... If you want to fetch from securityhub and file-asff at the same time use --inputs file-asff securityhub"
            )
            exit(1)

    # Validate file-asff
    if "file-asff" in args.inputs:
        if not args.input_asff:
            logger.error(
                "file-asff input specified but not --input-asff, specify the input file with --input-asff"
            )
            exit(1)
        try:
            with open(args.input_asff) as f:
                asff_findings = json.load(f)
        except (json.decoder.JSONDecodeError, FileNotFoundError) as err:
            logger.error("--input-asff file %s %s!", args.input_asff, str(err))
            exit(1)
    else:
        asff_findings = False

    # Validate Security Hub Filters
    if not args.sh_filters and not args.sh_template:
        default_sh_filters = {
            "RecordState": ["ACTIVE"],
            "WorkflowStatus": ["NEW"],
            "ProductName": ["Security Hub"],
        }
        sh_filters = set_sh_filters(default_sh_filters)
    elif args.sh_template:
        from pathlib import Path

        import yaml

        try:
            yaml_to_dict = yaml.safe_load(Path(args.sh_template).read_text())
            dict_values = next(iter(yaml_to_dict.values()))
            sh_filters = dict_values
        except (yaml.scanner.ScannerError, FileNotFoundError) as err:
            logger.error("SH Template %s reading error: %s", args.sh_template, str(err))
            exit(1)
    else:
        sh_filters = args.sh_filters
        sh_filters = set_sh_filters(sh_filters)

    # Validate MetaChecks filters
    if args.mh_filters_checks and not args.meta_checks:
        logger.error(
            "--mh-filters-checks provided but --meta-checks are disabled, ignoring..."
        )
    mh_filters_checks = args.mh_filters_checks or {}
    for mh_filter_check_key, mh_filter_check_value in mh_filters_checks.items():
        if mh_filters_checks[mh_filter_check_key].lower() == "true":
            mh_filters_checks[mh_filter_check_key] = bool(True)
        elif mh_filters_checks[mh_filter_check_key].lower() == "false":
            mh_filters_checks[mh_filter_check_key] = bool(False)
        else:
            logger.error(
                "MetaHub Filter Only True/False Supported: " + str(mh_filters_checks)
            )
            exit(1)

    # Validate MetaTags filters
    if args.mh_filters_tags and not args.meta_tags:
        logger.error(
            "--mh-filters-tags provided but --meta-tags are disabled, ignoring..."
        )
    mh_filters_tags = args.mh_filters_tags or {}

    # Parameter Validation: --sh-account and --sh-assume-role
    if bool(args.sh_account) != bool(args.sh_assume_role):
        logger.error(
            "Parameter error: --sh-assume-role and sh-account must be provided together, but only 1 provided."
        )
        exit(1)

    # AWS Account
    if not args.sh_account:
        sh_account = get_account_id(logger)
        sh_account_alias = get_account_alias(logger)
    else:
        sh_account = args.sh_account
        sh_account_alias = get_account_alias(logger, sh_account, args.sh_assume_role)
    sh_account_alias_str = (
        " (" + str(sh_account_alias) + ")" if str(sh_account_alias) else ""
    )

    # AWS Region
    sh_region = args.sh_region or get_region(logger)

    # SH Aggregator
    sh_region_aggregator = False
    if sh_region:
        sh_region_aggregator = get_sh_findings_aggregator(logger, sh_region)
    if sh_region_aggregator:
        if sh_region_aggregator != sh_region:
            logger.error(
                "You are using region %s, but your findings aggregator is in region: %s. Use --sh-region %s for aggregated findings...",
                sh_region,
                sh_region_aggregator,
                sh_region_aggregator,
            )

    # Validate Security Hub input
    if "securityhub" in args.inputs and (not sh_region or not sh_account):
        logger.error(
            "AWS Region or Account not found, but Security Hub defined as input. Set Credentials and/or use --sh-region and --sh-account."
        )
        exit(1)

    return (
        asff_findings,
        sh_filters,
        mh_filters_checks,
        mh_filters_tags,
        sh_account,
        sh_account_alias_str,
        sh_region,
    )


def generate_outputs(args, mh_findings_short, mh_inventory, mh_statistics, mh_findings):

    # Columns for CSV and HTML
    metachecks_columns = args.output_meta_checks_columns or mh_statistics["metachecks"]
    metatags_columns = args.output_meta_tags_columns or mh_statistics["metatags"]

    # Output JSON files
    if "json" in args.output_modes:
        if mh_findings:
            for out in args.outputs:
                print_title_line("Output JSON: " + out)
                WRITE_FILE = f"{OUTPUT_DIR}metahub-{out}-{TIMESTRF}.json"
                with open(WRITE_FILE, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "short": mh_findings_short,
                            "inventory": mh_inventory,
                            "statistics": mh_statistics,
                            "full": mh_findings,
                        }[out],
                        f,
                        indent=2,
                    )
                print_table("File: ", WRITE_FILE)

    # Output HTML files
    if "html" in args.output_modes:
        print_title_line("Output HTML")
        import jinja2

        if mh_findings:
            WRITE_FILE = f"{OUTPUT_DIR}metahub-{TIMESTRF}.html"
            templateLoader = jinja2.FileSystemLoader(searchpath="./")
            templateEnv = jinja2.Environment(loader=templateLoader)
            TEMPLATE_FILE = "lib/html/template.html"
            template = templateEnv.get_template(TEMPLATE_FILE)
            with open(WRITE_FILE, "w", encoding="utf-8") as f:
                html = template.render(
                    data=mh_findings,
                    statistics=mh_statistics,
                    title="MetaHub",
                    metachecks_columns=metachecks_columns,
                    metatags_columns=metatags_columns,
                )
                f.write(html)
            print_table("File: ", WRITE_FILE)

    # Output CSV files
    if "csv" in args.output_modes:
        print_title_line("Output CSV")
        import csv

        def output_csv(output):
            new_list = []
            for key, dictionary in output.items():
                new_dict = {"ARN": key}
                for column in metatags_columns:
                    try:
                        dictionary[column] = dictionary["metatags"][column]
                    except (KeyError, TypeError):
                        dictionary[column] = ""
                for column in metachecks_columns:
                    try:
                        dictionary[column] = dictionary["metachecks"][column]
                    except (KeyError, TypeError):
                        dictionary[column] = ""
                new_dict.update(dictionary)
                new_list.append(new_dict)
            columns = new_list[0].keys()
            return columns, new_list

        if mh_findings:
            WRITE_FILE = f"{OUTPUT_DIR}metahub-{TIMESTRF}.csv"
            with open(WRITE_FILE, "w", encoding="utf-8", newline="") as output_file:
                columns, csv_list = output_csv(mh_findings_short)
                dict_writer = csv.DictWriter(output_file, columns)
                dict_writer.writeheader()
                dict_writer.writerows(csv_list)
            print_table("File: ", WRITE_FILE)


def main(args):
    parser = get_parser()
    args = parser.parse_args(args)
    banners = args.banners
    print_banner(banners)
    test_python_version()
    logger = get_logger(args.log_level)

    if args.list_meta_checks:
        from lib.metachecks.metachecks import list_metachecks

        print_title_line("List MetaChecks", banners=banners)
        list_metachecks(logger)
        return

    (
        asff_findings,
        sh_filters,
        mh_filters_checks,
        mh_filters_tags,
        sh_account,
        sh_account_alias_str,
        sh_region,
    ) = validate_arguments(args, logger)

    print_title_line("Options", banners=banners)
    print_table(
        "Security Hub Account: ",
        str(sh_account) + sh_account_alias_str,
        banners=banners,
    )
    print_table("Security Hub Role: ", str(args.sh_assume_role), banners=banners)
    print_table("Security Hub Region: ", sh_region, banners=banners)
    print_table("Security Hub filters: ", str(sh_filters), banners=banners)
    print_table("Security Hub yaml: ", str(args.sh_template), banners=banners)
    print_table("MetaHub Role: ", str(args.mh_assume_role), banners=banners)
    print_table("MetaChecks: ", str(args.meta_checks), banners=banners)
    print_table("MetaChecks Filters: ", str(mh_filters_checks), banners=banners)
    print_table("Drilled Down Mode: ", str(args.drill_down), banners=banners)
    print_table("MetaTags: ", str(args.meta_tags), banners=banners)
    print_table("MetaTags Filters: ", str(mh_filters_tags), banners=banners)
    print_table("MetaTrails: ", str(args.meta_trails), banners=banners)
    print_table("Update Findings: ", str(args.update_findings), banners=banners)
    print_table("Enrich Findings: ", str(args.enrich_findings), banners=banners)
    print_table("Output: ", str(args.outputs), banners=banners)
    print_table("Output Modes: ", str(args.output_modes), banners=banners)
    print_table("Input: ", str(args.inputs), banners=banners)
    print_table("Log Level: ", str(args.log_level), banners=banners)

    # Generate Findings
    print_title_line("Generating Findings", banners=banners)
    (mh_findings, mh_findings_short, mh_inventory, mh_statistics,) = generate_findings(
        logger,
        sh_filters,
        metachecks=args.meta_checks,
        mh_filters_checks=mh_filters_checks,
        metatags=args.meta_tags,
        mh_filters_tags=mh_filters_tags,
        sh_account=sh_account,
        sh_role=args.sh_assume_role,
        mh_role=args.mh_assume_role,
        sh_region=sh_region,
        inputs=args.inputs,
        asff_findings=asff_findings,
        metatrails=args.meta_trails,
        banners=banners,
        drill_down=args.drill_down,
    )

    if args.list_findings:
        if mh_findings:
            for out in args.outputs:
                print_title_line("List Findings: " + out, banners=banners)
                print(
                    json.dumps(
                        {
                            "short": mh_findings_short,
                            "inventory": mh_inventory,
                            "statistics": mh_statistics,
                            "full": mh_findings,
                        }[out],
                        indent=2,
                    )
                )

    if "lambda" in args.output_modes:
        if mh_findings:
            for out in args.outputs:
                if out == "short":
                    return mh_findings_short
                if out == "inventory":
                    return mh_inventory
                if out == "statistics":
                    return mh_inventory
                if out == "full":
                    return mh_findings

    generate_outputs(args, mh_findings_short, mh_inventory, mh_statistics, mh_findings)

    print_title_line("Results", banners=banners)
    print_table("Total Resources: ", str(len(mh_findings)), banners=banners)
    print_table(
        "Total Findings: ", str(count_mh_findings(mh_findings)), banners=banners
    )

    if args.update_findings:
        UPProcessedFindings = []
        UPUnprocessedFindings = []
        print_title_line("Update Findings", banners=banners)
        print_table(
            "Findings to update: ", str(count_mh_findings(mh_findings)), banners=banners
        )
        print_table("Update: ", str(args.update_findings), banners=banners)
        if mh_findings:
            UPProcessedFindings, UPUnprocessedFindings = update_findings(
                logger,
                mh_findings,
                args.update_findings,
                sh_account,
                args.sh_assume_role,
                sh_region,
            )
        print_title_line("Results", banners=banners)
        print_table(
            "ProcessedFindings: ", str(len(UPProcessedFindings)), banners=banners
        )
        print_table(
            "UnprocessedFindings: ", str(len(UPUnprocessedFindings)), banners=banners
        )

    if args.enrich_findings:
        ENProcessedFindings = []
        ENUnprocessedFindings = []
        print_title_line("Enrich Findings", banners=banners)
        print_table(
            "Findings to enrich: ", str(count_mh_findings(mh_findings)), banners=banners
        )
        if mh_findings:
            ENProcessedFindings, ENUnprocessedFindings = enrich_findings(
                logger, mh_findings, sh_account, args.sh_assume_role, sh_region
            )
        print_title_line("Results", banners=banners)
        print_table(
            "ProcessedFindings: ", str(len(ENProcessedFindings)), banners=banners
        )
        print_table(
            "UnprocessedFindings: ", str(len(ENUnprocessedFindings)), banners=banners
        )


if __name__ == "__main__":
    main(argv[1:])
