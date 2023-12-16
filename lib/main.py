from sys import argv, exit

from lib.actions import Actions
from lib.findings import generate_findings
from lib.helpers import (
    get_logger,
    get_parser,
    print_banner,
    print_table,
    print_title_line,
    test_python_version,
    validate_arguments,
)
from lib.outputs import Outputs
from lib.securityhub import SecurityHub


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

    def print_options():
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

    # Options
    print_title_line("Options", banners=banners)
    print_options()

    # Reading Findings
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

    # Outputs
    outputs = Outputs(
        logger, mh_findings, mh_findings_short, mh_inventory, mh_statistics, args
    )

    # List Findings
    outputs.list_findings()

    # Results
    print_title_line("Results", banners=banners)
    outputs.show_results()

    # Statistics
    print_title_line("Statistics by Findings", banners=banners)
    outputs.generate_output_rich()

    # Outputs Files
    print_title_line("Outputs", banners=banners)
    outputs.generate_outputs()

    if args.update_findings:
        sh = SecurityHub(
            logger, sh_region, sh_account, args.sh_assume_role, args.sh_profile
        )
        Actions(logger, args, mh_findings, sh).update_findings(update_findings_filters)

    if args.enrich_findings:
        sh = SecurityHub(
            logger, sh_region, sh_account, args.sh_assume_role, args.sh_profile
        )
        Actions(logger, args, mh_findings, sh).enrich_findings()

    if "lambda" in args.output_modes:
        return mh_findings_short


if __name__ == "__main__":
    main(argv[1:])
