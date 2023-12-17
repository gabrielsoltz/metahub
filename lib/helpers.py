import argparse
import json
import logging
import sys

from lib.AwsHelpers import (
    get_account_alias,
    get_account_id,
    get_available_regions,
    get_region,
)
from lib.config.configuration import sh_default_filters
from lib.securityhub import set_sh_filters


class KeyValueWithList(argparse.Action):
    """Parser keyvalue with list Action"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, Dictlist())
        logger = get_logger("ERROR")
        for value in values:
            # split it into key and value
            try:
                key, value = value.split("=")
            except ValueError:
                logger.error("ERROR: Incorrect Key=Value format: " + value)
                exit(1)
            # Dictionary:
            getattr(namespace, self.dest)[key] = value


class KeyValue(argparse.Action):
    """Parser keyvalue Action"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, dict())
        logger = get_logger("ERROR")
        for value in values:
            # split it into key and value
            try:
                key, value = value.split("=")
            except ValueError:
                logger.error("ERROR: Incorrect Key=Value format: " + value)
                exit(1)
            # Dictionary:
            getattr(namespace, self.dest)[key] = value


class Dictlist(dict):
    def __setitem__(self, key, value):
        try:
            self[key]
        except KeyError:
            super(Dictlist, self).__setitem__(key, [])
        self[key].append(value)


def get_parser():
    """Configure Parser"""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
    Metahub: the command line utility for AWS Security Hub.
    """,
    )

    # Group: Security Hub
    group_security_hub = parser.add_argument_group("Security Findings Options")
    group_security_hub.add_argument(
        "--sh-assume-role",
        default=None,
        help="Specify the AWS IAM role to be assumed where Security Hub is running. Use with --sh-account",
        required=False,
    )
    group_security_hub.add_argument(
        "--sh-account",
        default=None,
        help="Specify the AWS Account ID where Security Hub is running. Use with --sh-assume-role",
        required=False,
    )
    group_security_hub.add_argument(
        "--sh-region",
        choices=get_available_regions(get_logger("ERROR"), "securityhub"),
        default=[],
        help="Specify the AWS Region where Security Hub is running",
        required=False,
    )
    group_security_hub.add_argument(
        "--sh-profile",
        default=None,
        help="Specify the AWS authentication profile Profile to use for Security Hub",
        required=False,
    )
    group_security_hub.add_argument(
        "--sh-filters",
        default=None,
        help='Use this option to filter the results from Security Hub using key=value pairs, for example SeverityLabel=CRITICAL. Do not do not put spaces before or after the = sign. If a value contains spaces, you should define it with double quotes. By default ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW',
        required=False,
        nargs="*",
        action=KeyValueWithList,
    )
    group_security_hub.add_argument(
        "--sh-template",
        default=None,
        help="Use this option to filter the results from Security Hub using a YAML file. You need to specify the file: --sh-template templates/default.yml",
        required=False,
    )
    group_security_hub.add_argument(
        "--inputs",
        choices=["securityhub", "file-asff"],
        default=["securityhub"],
        nargs="+",
        help="Specify the source input for ingesting findings, by default is securityhub but you can also use one or more ASFF files (--inputs file-asff) or boths inputs together (--inputs securityhub file-asff)and combine them",
        required=False,
    )
    group_security_hub.add_argument(
        "--input-asff",
        default=None,
        nargs="+",
        help="Specify the ASFF file path when the previous option is set in file-asff (--input-asff /path/to/file-asff-1 /path/to/file-asff-2)",
        required=False,
    )

    # Group: Security Hub Actions
    group_actions = parser.add_argument_group("Security Hub Actions")
    group_actions.add_argument(
        "--update-findings",
        default=None,
        help='Use this option to update the result findings Workflow Status (with a Note). Use --update-findings Workflow=NOTIFIED|RESOLVED|SUPPRESSED|NEW Note="You can whatever you like here, like a ticket ID, you will see this Note on your SH "Updated at" colum',
        required=False,
        nargs="*",
        action=KeyValue,
    )
    group_actions.add_argument(
        "--enrich-findings",
        help="Use this option to enrich your security findings directly in Security Hub with the contextual information using the field: UserDefinedFields.",
        required=False,
        action=argparse.BooleanOptionalAction,
    )
    group_actions.add_argument(
        "--actions-confirmation",
        default=True,
        help="Use this option to execute the security hub actions without confirmation",
        required=False,
        action=argparse.BooleanOptionalAction,
    )

    # Group: Context Options
    group_meta_checks = parser.add_argument_group("Context Options")
    group_meta_checks.add_argument(
        "--mh-filters-config",
        default=None,
        help="Use this option to filter the resources based on context results using key=True/False pairs, for example public=True. Only True or False are supported as values. You can combine one or more filters using spaces",
        required=False,
        nargs="*",
        action=KeyValue,
    )
    group_meta_checks.add_argument(
        "--mh-filters-tags",
        default=None,
        help="Use this option to filter the resources based on Tags results using key=value pairs, for example environment=production. If a value contains spaces, you should define it with double quotes. You can combine one or more filters using spaces",
        required=False,
        nargs="*",
        action=KeyValue,
    )
    group_meta_checks.add_argument(
        "--mh-assume-role",
        default=None,
        help="Specify the AWS IAM role role to be assumed where the affected resources are running",
        required=False,
    )
    group_meta_checks.add_argument(
        "--context",
        default=[
            "config",
            "tags",
            "account",
        ],
        help="This option defines which actions MetaHub will execute to get the context of the affected resources. By default, MetaHub will execute config and tags actions. CloudTrail and Account are disabled by default as could be expensive to execute and requires non-standard iam actions policies. Check that before enabling them",
        choices=[
            "config",
            "tags",
            "account",
            "cloudtrail",
        ],
        nargs="*",
        required=False,
    )

    # Group: Output Options
    group_output = parser.add_argument_group("Output Options")
    group_output.add_argument(
        "--list-findings",
        choices=["short", "full", "inventory", "statistics"],
        default=[],
        nargs="+",
        help="Specify if you want to see the results in your terminal and how: --list-findings short inventory",
        required=False,
    )
    group_output.add_argument(
        "--output-modes",
        choices=[
            "json-short",
            "json-full",
            "json-statistics",
            "json-inventory",
            "html",
            "csv",
            "xlsx",
            "lambda",
        ],
        default=[
            "json-short",
            "json-full",
            "json-statistics",
            "json-inventory",
            "html",
            "csv",
            "xlsx",
        ],
        nargs="*",
        help="Specify the Outputs you want to generate. By deafault all of them are enabled. If you only want HTML and XLSX: --output-modes html xlsx",
        required=False,
    )
    group_output.add_argument(
        "--output-tag-columns",
        help="Customize the Tags to use as columns in the outputs: csv, html and xlsx. Also in the configuration file.",
        default=[],
        nargs="+",
        required=False,
    )
    group_output.add_argument(
        "--output-config-columns",
        help="Customize the Configs properties to use as columns in the outputs: csv, html and xlsx. Also in the configuration file.",
        default=[],
        nargs="+",
        required=False,
    )
    group_output.add_argument(
        "--output-account-columns",
        help="Customize the Account properties to use as columns in the outputs: csv, html and xlsx. Also in the configuration file.",
        default=[],
        nargs="+",
        required=False,
    )
    group_output.add_argument(
        "--banners",
        help="Show banners and titles",
        default=True,
        required=False,
        action=argparse.BooleanOptionalAction,
    )

    # Group: Debug Options
    group_debug = parser.add_argument_group("Debug Options")
    group_debug.add_argument(
        "--log-level",
        choices=["ERROR", "WARNING", "INFO", "DEBUG"],
        default="ERROR",
        help="Specify Log Level, by default ERROR",
        required=False,
    )

    return parser


def get_logger(log_level):
    """Configure Logger"""
    logger = logging.getLogger()
    for handler in logger.handlers:
        logger.removeHandler(handler)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(process)d - %(filename)s:%(funcName)s - [%(levelname)s] %(message)s",
    )
    return logger


color = {
    "PURPLE": "\033[95m",
    "CYAN": "\033[96m",
    "DARKCYAN": "\033[36m",
    "BLUE": "\033[94m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "RED": "\033[91m",
    "BOLD": "\033[1m",
    "UNDERLINE": "\033[4m",
    "END": "\033[0m",
    "CRITICAL": "\033[91m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
}


def print_banner(banners=True):
    if not banners:
        return
    print(
        r" "
        + color["BOLD"]
        + "______  ___    _____       ______  __      ______  "
        + color["END"]
    )
    print(
        r" "
        + color["BOLD"]
        + "___   |/  /______  /______ ___  / / /___  ____  /_ "
        + color["END"]
    )
    print(
        r" "
        + color["BOLD"]
        + "__  /|_/ /_  _ \  __/  __ `/_  /_/ /_  / / /_  __ \\"
        + color["END"]
    )
    print(
        r" "
        + color["BOLD"]
        + "_  /  / / /  __/ /_ / /_/ /_  __  / / /_/ /_  /_/ /"
        + color["END"]
    )
    print(
        r" "
        + color["BOLD"]
        + "/_/  /_/  \___/\__/ \__,_/ /_/ /_/  \__,_/ /_.___/ "
        + color["END"]
    )
    print(
        r"  "
        + color["DARKCYAN"]
        + "Impact-Contextual Vulnerability Management"
        + color["END"]
    )


def print_table(key, value, keycolor=color["DARKCYAN"], banners=True):
    if not banners:
        return
    # print(keycolor + key + color["END"], " \t", value)
    tabs = "\t\t"
    if (len(key)) > 14:
        tabs = "\t"
    print(keycolor + key + color["END"], tabs, value)


def print_color(value, keycolor=color["DARKCYAN"], banners=True):
    if not banners:
        return
    print(keycolor + value + color["END"])


def print_title_line(text, ch="-", length=78, banners=True):
    if not banners:
        return
    if text:
        spaced_text = " %s " % text
    else:
        spaced_text = text
    colored_text = color["BOLD"] + spaced_text + color["END"]
    banner = colored_text.center(length, ch)
    print("\n" + banner)


def confirm_choice(message, actions_confirmation=True):
    """Simple function to confirm the action, returns True or False based on user entry"""
    if actions_confirmation:
        confirm = input(message + " [c]Confirm or [v]Void: ")
        if confirm != "c" and confirm != "v":
            print("\n Invalid Option. Please Enter a Valid Option.")
            return confirm_choice(message)
        if confirm == "c":
            return True
        return False
    else:
        print("Actions confirmation disabled: continuing with the action...")
        return True


def test_python_version():
    """Check Python Version"""
    logger = get_logger("ERROR")
    if sys.version_info < (3, 9):
        logger.error(
            "Python Version must be Python 3.9 or above. Please update your Python version: %s",
            sys.version,
        )
        return False
    return True


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
