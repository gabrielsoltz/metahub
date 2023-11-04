import argparse
import logging
import sys

from rich.panel import Panel

from lib.AwsHelpers import get_available_regions


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
    group_security_hub = parser.add_argument_group("Security Hub Options")
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
        "--sh-profile",
        default=None,
        help="AWS Profile to use for Security Hub",
        required=False,
    )
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
        nargs="+",
        help="Specify ASFF file path for use with --input-asff file-asff-1, file-asff-2",
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
        help="Use this option to update the results findings UserDefinedFields with the output of Meta Checks and/or Meta Tags.",
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

    # Group: Meta Options
    group_meta_checks = parser.add_argument_group("Meta Options")
    group_meta_checks.add_argument(
        "--mh-filters-config",
        default=None,
        help="Use this option to filter the resources based on Context Config results using key=value pairs, for example is_public=True. Only True or False. You can combine one or more filters using spaces",
        required=False,
        nargs="*",
        action=KeyValue,
    )
    group_meta_checks.add_argument(
        "--mh-filters-tags",
        default=None,
        help="Use this option to filter the resources based on Context Tags results using key=value pairs, for example environment=production. If a value contains spaces, you should define it with double quotes. You can combine one or more filters using spaces",
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
        help="",
        choices=[
            "config",
            "tags",
            "account",
            "cloudtrail",
        ],
        default=[
            "config",
            "tags",
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
        help="Specify the output you want, by default short. Combine one or more using spaces",
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
        help="Specify the output mode, by default json. Combine one or more using spaces",
        required=False,
    )
    group_output.add_argument(
        "--output-tag-columns",
        help="Specify which Tags to unroll as Columns for outputs (csv, html and xlsx)",
        default=[],
        nargs="+",
        required=False,
    )
    group_output.add_argument(
        "--output-config-columns",
        help="Specify which Configs to unroll as Columns for outputs (csv, html and xlsx)",
        default=[],
        nargs="+",
        required=False,
    )
    group_output.add_argument(
        "--output-account-columns",
        help="Specify which Account to unroll as Columns for outputs (csv, html and xlsx)",
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


def rich_box(resource_type, values):
    title = resource_type
    value = values
    # return f"[b]{title}[/b]\n[yellow]{value}"
    return f"[b]{title.center(20)}[/b]\n[bold][yellow]{str(value).center(20)}"


def rich_box_severity(severity, values):
    color = {
        "CRITICAL": "red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFORMATIONAL": "white",
    }
    title = "[" + color[severity] + "] " + severity + "[/]"
    value = values
    return f"[b]{title.center(5)}[/b]\n[bold]{str(value).center(5)}"


def generate_rich(mh_statistics):
    severity_renderables = []
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        severity_renderables.append(
            Panel(
                rich_box_severity(
                    severity, mh_statistics["SeverityLabel"].get(severity, 0)
                ),
                expand=False,
                padding=(1, 10),
            )
        )
    resource_type_renderables = [
        Panel(rich_box(resource_type, values), expand=True)
        for resource_type, values in mh_statistics["ResourceType"].items()
    ]
    workflows_renderables = [
        Panel(rich_box(workflow, values), expand=True)
        for workflow, values in mh_statistics["Workflow"].items()
    ]
    region_renderables = [
        Panel(rich_box(Region, values), expand=True)
        for Region, values in mh_statistics["Region"].items()
    ]
    accountid_renderables = [
        Panel(rich_box(AwsAccountId, values), expand=True)
        for AwsAccountId, values in mh_statistics["AwsAccountId"].items()
    ]
    recordstate_renderables = [
        Panel(rich_box(RecordState, values), expand=True)
        for RecordState, values in mh_statistics["RecordState"].items()
    ]
    compliance_renderables = [
        Panel(rich_box(Compliance, values), expand=True)
        for Compliance, values in mh_statistics["Compliance"].items()
    ]
    return (
        severity_renderables,
        resource_type_renderables,
        workflows_renderables,
        region_renderables,
        accountid_renderables,
        recordstate_renderables,
        compliance_renderables,
    )
