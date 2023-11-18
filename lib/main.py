import json
from sys import argv, exit

from rich.columns import Columns
from rich.console import Console

from lib.AwsHelpers import get_account_alias, get_account_id, get_region
from lib.config.configuration import sh_default_filters
from lib.findings import enrich_findings, generate_findings, update_findings
from lib.helpers import (
    generate_rich,
    get_logger,
    get_parser,
    print_banner,
    print_color,
    print_table,
    print_title_line,
    test_python_version,
)
from lib.outputs import generate_outputs


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
        asff_findings = []
        for file in args.input_asff:
            try:
                with open(file) as f:
                    asff_findings.extend(json.load(f))
            except (json.decoder.JSONDecodeError, FileNotFoundError) as err:
                logger.error("--input-asff file %s %s!", args.input_asff, str(err))
                exit(1)
    elif args.input_asff and "file-asff" not in args.inputs:
        logger.error(
            "--input-asff specified but not file-asff input. Use --inputs file-asff to use --input-asff"
        )
        exit(1)
    else:
        asff_findings = False

    # Validate Security Hub Filters
    if not args.sh_filters and not args.sh_template:
        sh_filters = set_sh_filters(sh_default_filters)
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

    # Validate Config filters
    mh_filters_config = args.mh_filters_config or {}
    for mh_filter_config_key, mh_filter_config_value in mh_filters_config.items():
        if mh_filters_config[mh_filter_config_key].lower() == "true":
            mh_filters_config[mh_filter_config_key] = bool(True)
        elif mh_filters_config[mh_filter_config_key].lower() == "false":
            mh_filters_config[mh_filter_config_key] = bool(False)
        else:
            logger.error(
                "Only True or False it is supported for Context Config filters: "
                + str(mh_filters_config)
            )
            exit(1)

    # Validate Tags filters
    mh_filters_tags = args.mh_filters_tags or {}

    # Parameter Validation: --sh-account and --sh-assume-role
    if bool(args.sh_account) != bool(args.sh_assume_role):
        logger.error(
            "Parameter error: --sh-assume-role and sh-account must be provided together, but only 1 provided."
        )
        exit(1)

    # AWS Security Hub
    if "securityhub" in args.inputs:
        sh_region = args.sh_region or get_region(logger)
        sh_account = args.sh_account or get_account_id(
            logger, sess=None, profile=args.sh_profile
        )
        sh_account_alias = get_account_alias(
            logger, sh_account, role_name=args.sh_assume_role, profile=args.sh_profile
        )
    else:
        sh_region = args.sh_region
        sh_account = args.sh_account
        sh_account_alias = ""
    sh_account_alias_str = (
        " (" + str(sh_account_alias) + ")" if str(sh_account_alias) else ""
    )

    # Validate Security Hub input
    if "securityhub" in args.inputs and (not sh_region or not sh_account):
        logger.error(
            "Security Hub is defined as input for findings, but no region or account was found. Check your credentials and/or use --sh-region and --sh-account."
        )
        exit(1)

    # Validate udpate findings
    update_findings_filters = {}
    if args.update_findings:
        IsNnoteProvided = False
        IsAllowedKeyProvided = False
        for key, value in args.update_findings.items():
            if key in ("Workflow", "Note"):
                if key == "Workflow":
                    WorkflowValues = ("NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED")
                    if value not in WorkflowValues:
                        logger.error(
                            "Incorrect update findings workflow value. Use: "
                            + str(WorkflowValues)
                        )
                        exit(1)
                    Workflow = {"Workflow": {"Status": value}}
                    update_findings_filters.update(Workflow)
                    IsAllowedKeyProvided = True
                if key == "Note":
                    Note = {"Note": {"Text": value, "UpdatedBy": "MetaHub"}}
                    update_findings_filters.update(Note)
                    IsNnoteProvided = True
                continue
            logger.error(
                "Unsuported update findings key: "
                + str(key)
                + " - Supported keys: Workflow and Note. Use --update-findings Workflow=NEW Note='This is an example Note'"
            )
            exit(1)
        if not IsAllowedKeyProvided or not IsNnoteProvided:
            logger.error(
                'Update findings missing key. Use --update-findings Workflow=NEW Note="This is an example Note"'
            )
            exit(1)

    return (
        asff_findings,
        sh_filters,
        mh_filters_config,
        mh_filters_tags,
        sh_account,
        sh_account_alias_str,
        sh_region,
        update_findings_filters,
    )


def main(args):
    parser = get_parser()
    args = parser.parse_args(args)
    banners = args.banners
    print_banner(banners)
    if not test_python_version():
        exit(1)
    logger = get_logger(args.log_level)

    (
        asff_findings,
        sh_filters,
        mh_filters_config,
        mh_filters_tags,
        sh_account,
        sh_account_alias_str,
        sh_region,
        update_findings_filters,
    ) = validate_arguments(args, logger)

    print_title_line("Options", banners=banners)
    print_table("Input: ", str(args.inputs), banners=banners)
    print_table(
        "Security Hub Account: ",
        str(sh_account) + sh_account_alias_str,
        banners=banners,
    )
    print_table("Security Hub Region: ", sh_region, banners=banners)
    print_table("Security Hub Role: ", str(args.sh_assume_role), banners=banners)
    print_table("Security Hub Profile: ", args.sh_profile, banners=banners)
    print_table("Security Hub filters: ", str(sh_filters), banners=banners)
    print_table("Security Hub yaml: ", str(args.sh_template), banners=banners)
    print_table("Input File: ", str(args.input_asff), banners=banners)
    print_table("Context Role: ", str(args.mh_assume_role), banners=banners)
    print_table("Context Options: ", str(args.context), banners=banners)
    print_table("Config Filters: ", str(mh_filters_config), banners=banners)
    print_table("Tags Filters: ", str(mh_filters_tags), banners=banners)
    print_table("Update Findings: ", str(args.update_findings), banners=banners)
    print_table("Enrich Findings: ", str(args.enrich_findings), banners=banners)
    print_table(
        "Actions Confirmation: ", str(args.actions_confirmation), banners=banners
    )
    print_table("Output Modes: ", str(args.output_modes), banners=banners)
    print_table("List Findings: ", str(args.list_findings), banners=banners)
    print_table("Log Level: ", str(args.log_level), banners=banners)

    # Generate Findings
    print_title_line("Reading Findings", banners=banners)
    (
        mh_findings,
        mh_findings_short,
        mh_inventory,
        mh_statistics,
    ) = generate_findings(
        logger,
        sh_filters,
        sh_region=sh_region,
        sh_account=sh_account,
        sh_profile=args.sh_profile,
        sh_role=args.sh_assume_role,
        context=args.context,
        mh_role=args.mh_assume_role,
        mh_filters_config=mh_filters_config,
        mh_filters_tags=mh_filters_tags,
        inputs=args.inputs,
        asff_findings=asff_findings,
        banners=banners,
    )

    if mh_findings:
        for out in args.list_findings:
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

    print_title_line("Results", banners=banners)
    print_table(
        "Total Findings: ", str(count_mh_findings(mh_findings)), banners=banners
    )
    print_table("Total Resources: ", str(len(mh_findings)), banners=banners)

    print_title_line("Statistics by Findings", banners=banners)
    if banners:
        (
            severity_renderables,
            resource_type_renderables,
            workflows_renderables,
            region_renderables,
            accountid_renderables,
            recordstate_renderables,
            compliance_renderables,
        ) = generate_rich(mh_statistics)
        console = Console()
        print_color("Severities:")
        # console.print(Align.center(Group(Columns(severity_renderables))))
        console.print(Columns(severity_renderables), end="")
        print_color("Resource Type:")
        console.print(Columns(resource_type_renderables))
        print_color("Workflow Status:")
        console.print(Columns(workflows_renderables))
        print_color("Compliance Status:")
        console.print(Columns(compliance_renderables))
        print_color("Record State:")
        console.print(Columns(recordstate_renderables))
        print_color("Region:")
        console.print(Columns(region_renderables))
        print_color("Account ID:")
        console.print(Columns(accountid_renderables))

    print_title_line("Outputs", banners=banners)
    generate_outputs(
        args,
        mh_findings_short,
        mh_inventory,
        mh_statistics,
        mh_findings,
        banners=banners,
    )

    if args.update_findings:
        UPProcessedFindings = []
        UPUnprocessedFindings = []
        print_title_line("Update Findings", banners=banners)
        print_table(
            "Findings to update: ", str(count_mh_findings(mh_findings)), banners=banners
        )
        print_table("Update: ", str(args.update_findings), banners=banners)
        if "lambda" in args.output_modes:
            print(
                "Updating findings: ",
                str(count_mh_findings(mh_findings)),
                "with:",
                str(args.update_findings),
            )
        if mh_findings:
            UPProcessedFindings, UPUnprocessedFindings = update_findings(
                logger,
                mh_findings,
                args.update_findings,
                sh_account,
                args.sh_assume_role,
                sh_region,
                update_findings_filters,
                args.sh_profile,
                args.actions_confirmation,
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
        if "lambda" in args.output_modes:
            print("Enriching findings: ", str(count_mh_findings(mh_findings)))
        if mh_findings:
            ENProcessedFindings, ENUnprocessedFindings = enrich_findings(
                logger,
                mh_findings,
                sh_account,
                args.sh_assume_role,
                sh_region,
                args.sh_profile,
                args.actions_confirmation,
            )
        print_title_line("Results", banners=banners)
        print_table(
            "ProcessedFindings: ", str(len(ENProcessedFindings)), banners=banners
        )
        print_table(
            "UnprocessedFindings: ", str(len(ENUnprocessedFindings)), banners=banners
        )

    if "lambda" in args.output_modes:
        return mh_findings_short


if __name__ == "__main__":
    main(argv[1:])
