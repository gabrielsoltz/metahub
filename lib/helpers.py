import argparse
import logging
import sys

from lib.AwsHelpers import get_available_regions


class KeyValueWithList(argparse.Action):
    """Parser keyvalue with list Action"""

    def __call__(self, parser, namespace, values, option_string=None):
        # setattr(namespace, self.dest, dict())
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
    group_security_hub = parser.add_argument_group("Security Hub Options")
    group_security_hub.add_argument(
        "--sh-filters",
        default=None,
        help='Use this option to filter the results from SH using key=value pairs, for example SeverityLabel=CRITICAL. Do not do not put spaces before or after the = sign. If a value contains spaces, you should define it with double quotes. By default ProductName="Security Hub" RecordState=ACTIVE WorkflowStatus=NEW',
        required=False,
        nargs="*",
        action=KeyValueWithList,
    )
    group_security_hub.add_argument(
        "--sh-template",
        default=None,
        help="Use this option to filter the results from SH using a YAML file. You need to specify the file: --sh-template templates/default.yml",
        required=False,
    )
    group_security_hub.add_argument(
        "--sh-assume-role",
        default=None,
        help="Specify the AWS IAM role to be assumed where SH is running. Use with --sh-account",
        required=False,
    )
    group_security_hub.add_argument(
        "--sh-account",
        default=None,
        help="Specify the AWS Account ID where SH is running. Use with --sh-assume-role",
        required=False,
    )
    group_security_hub.add_argument(
        "--sh-region",
        choices=get_available_regions(get_logger("ERROR"), "securityhub"),
        default=[],
        help="Specify the AWS Region where SH is running",
        required=False,
    )
    group_security_hub.add_argument(
        "--update-findings",
        default=None,
        help='Use this option to update the result findings Workflow Status (with a Note). Use --update-findings Workflow=NOTIFIED|RESOLVED|SUPPRESSED|NEW Note="You can whatever you like here, like a ticket ID, you will see this Note on your SH "Updated at" colum',
        required=False,
        nargs="*",
        action=KeyValue,
    )
    group_security_hub.add_argument(
        "--enrich-findings",
        help="Use this option to update the results findings UserDefinedFields with the output of Meta Checks and/or Meta Tags. Use with --meta-checks and/or --meta-tags",
        required=False,
        action=argparse.BooleanOptionalAction,
    )
    group_security_hub.add_argument(
        "--inputs",
        choices=["securityhub", "file-asff"],
        default=["securityhub"],
        nargs="+",
        help="Specify input source for findings, by default securityhub but you can also use an ASFF file (file-asff) or boths inputs together and combine them",
        required=False,
    )
    group_security_hub.add_argument(
        "--input-asff",
        default=None,
        help="Specify ASFF file path for use with --input file-asff",
        required=False,
    )

    # Group: Meta Checks and Meta Tags Options
    group_meta_checks = parser.add_argument_group("Meta Checks and Meta Tags Options")
    group_meta_checks.add_argument(
        "--list-meta-checks",
        help="Use this option to list all available Meta Checks",
        required=False,
        action=argparse.BooleanOptionalAction,
    )
    group_meta_checks.add_argument(
        "--meta-checks",
        help="Use this option to enable Meta Checks",
        required=False,
        action=argparse.BooleanOptionalAction,
    )
    group_meta_checks.add_argument(
        "--mh-filters-checks",
        default=None,
        help="Use this option to filter the resources based on Meta Checks results using key=value pairs, for example is_public=True. Only True or False. You can combine one or more filters using spaces",
        required=False,
        nargs="*",
        action=KeyValue,
    )
    group_meta_checks.add_argument(
        "--meta-tags",
        help="Use this option to enable Meta Tags",
        required=False,
        action=argparse.BooleanOptionalAction,
    )
    group_meta_checks.add_argument(
        "--meta-trails",
        help="Use this option to enable Meta Trails",
        required=False,
        action=argparse.BooleanOptionalAction,
    )
    group_meta_checks.add_argument(
        "--mh-filters-tags",
        default=None,
        help="Use this option to filter the resources based on Meta Tags results using key=value pairs, for example environment=production. If a value contains spaces, you should define it with double quotes. You can combine one or more filters using spaces",
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

    # Group: Output Options
    group_output = parser.add_argument_group("Output Options")
    group_output.add_argument(
        "--outputs",
        choices=["short", "full", "inventory", "statistics"],
        default=["short"],
        nargs="+",
        help="Specify the output you want, by default short. Combine one or more using spaces",
        required=False,
    )
    group_output.add_argument(
        "--list-findings",
        help="Use this option to show the ouput in the console prompt. All outputs will be shown, one by one",
        required=False,
        action=argparse.BooleanOptionalAction,
    )
    group_output.add_argument(
        "--output-modes",
        choices=["json", "html", "csv", "lambda"],
        default=["json"],
        nargs="*",
        help="Specify the output mode, by default json. Combine one or more using spaces",
        required=False,
    )
    group_output.add_argument(
        "--output-meta-tags-columns",
        help="Specify which Meta Tags to unroll as Columns for output csv and html",
        default=[],
        nargs="+",
        required=False,
    )
    group_output.add_argument(
        "--output-meta-checks-columns",
        help="Specify which Meta Checks to unroll as Columns for output csv and html",
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
        + "the command line utility for AWS Security Hub"
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


def confirm_choice(message):
    """Simple function to confirm the action, returns True or False based on user entry"""
    confirm = input(message + " [c]Confirm or [v]Void: ")
    if confirm != "c" and confirm != "v":
        print("\n Invalid Option. Please Enter a Valid Option.")
        return confirm_choice(message)
    if confirm == "c":
        return True
    return False


def test_python_version():
    """Check Python Version"""
    logger = get_logger("ERROR")
    if sys.version_info < (3, 9):
        logger.error(
            "Python Version must be Python 3.9 or above. Please update your Python version: %s",
            sys.version,
        )
        sys.exit(1)
