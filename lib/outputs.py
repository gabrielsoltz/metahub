import csv
import json
from time import strftime

import jinja2
import xlsxwriter
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel

from lib.config.configuration import (
    account_columns,
    config_columns,
    impact_columns,
    outputs_dir,
    outputs_time_str,
    tag_columns,
)
from lib.findings import count_mh_findings
from lib.helpers import print_color, print_table, print_title_line

TIMESTRF = strftime(outputs_time_str)


class Outputs:
    def __init__(
        self, logger, mh_findings, mh_findings_short, mh_inventory, mh_statistics, args
    ) -> None:
        self.logger = logger
        self.mh_findings = mh_findings
        self.mh_findings_short = mh_findings_short
        self.mh_inventory = mh_inventory
        self.mh_statistics = mh_statistics
        self.banners = args.banners
        self.args = args
        # Output Columns
        self.config_columns = (
            args.output_config_columns
            or config_columns
            or list(mh_statistics["config"].keys())
        )
        self.tag_columns = (
            args.output_tag_columns or tag_columns or list(mh_statistics["tags"].keys())
        )
        self.account_columns = (
            args.output_account_columns or account_columns or mh_statistics["account"]
        )
        self.impact_columns = impact_columns or mh_statistics["impact"]

    def generate_outputs(self):
        if self.mh_findings:
            for ouput_mode in self.args.output_modes:
                if ouput_mode.startswith("json"):
                    json_mode = ouput_mode.split("-")[1]
                    self.generate_output_json(
                        json_mode,
                    )
                if ouput_mode == "csv":
                    self.generate_output_csv()
                if ouput_mode == "xlsx":
                    self.generate_output_xlsx()
                if ouput_mode == "html":
                    self.generate_output_html()

    def generate_output_json(self, json_mode):
        WRITE_FILE = f"{outputs_dir}metahub-{json_mode}-{TIMESTRF}.json"
        with open(WRITE_FILE, "w", encoding="utf-8") as f:
            try:
                json.dump(
                    {
                        "short": self.mh_findings_short,
                        "full": self.mh_findings,
                        "inventory": self.mh_inventory,
                        "statistics": self.mh_statistics,
                    }[json_mode],
                    f,
                    indent=2,
                )
            except ValueError as e:
                print("Error generating JSON Output (" + json_mode + "):", e)
        print_table("JSON (" + json_mode + "): ", WRITE_FILE, banners=self.banners)

    def generate_output_csv(self):
        WRITE_FILE = f"{outputs_dir}metahub-{TIMESTRF}.csv"
        with open(WRITE_FILE, "w", encoding="utf-8", newline="") as output_file:
            colums = [
                "Resource ID",
                "Severity",
                "Impact",
                "Title",
                "AWS Account ID",
                "Region",
                "Resource Type",
                "WorkflowStatus",
                "RecordState",
                "ComplianceStatus",
            ]
            colums = (
                colums
                + self.config_columns
                + self.tag_columns
                + self.account_columns
                + self.impact_columns
            )
            dict_writer = csv.DictWriter(output_file, fieldnames=colums)
            dict_writer.writeheader()
            # Iterate over the resources
            for resource, values in self.mh_findings.items():
                for finding in values["findings"]:
                    for f, v in finding.items():
                        tag_column_values = []
                        for column in self.tag_columns:
                            try:
                                tag_column_values.append(values["tags"][column])
                            except (KeyError, TypeError):
                                tag_column_values.append("")
                        config_column_values = []
                        for column in self.config_columns:
                            try:
                                config_column_values.append(values["config"][column])
                            except (KeyError, TypeError):
                                config_column_values.append("")
                        impact_column_values = []
                        for column in self.impact_columns:
                            try:
                                impact_column_values.append(values["impact"][column])
                            except (KeyError, TypeError):
                                impact_column_values.append("")
                        account_column_values = []
                        for column in self.account_columns:
                            try:
                                account_column_values.append(values["account"][column])
                            except (KeyError, TypeError):
                                account_column_values.append("")
                        row = (
                            [
                                resource,
                                v.get("SeverityLabel", None),
                                (
                                    values.get("impact", None).get("Impact", None)
                                    if values.get("impact")
                                    else None
                                ),
                                f,
                                values.get("AwsAccountId", None),
                                values.get("Region", None),
                                values.get("ResourceType", None),
                                (
                                    v.get("Workflow", {}).get("Status", None)
                                    if v.get("Workflow")
                                    else None
                                ),
                                v.get("RecordState", None),
                                (
                                    v.get("Compliance", {}).get("Status", None)
                                    if v.get("Compliance")
                                    else None
                                ),
                            ]
                            # + impact_column_values
                            + account_column_values
                            + tag_column_values
                            + config_column_values
                        )
                        dict_writer.writerow(dict(zip(colums, row)))
        print_table("CSV:   ", WRITE_FILE, banners=self.banners)

    def generate_output_xlsx(self):
        WRITE_FILE = f"{outputs_dir}metahub-{TIMESTRF}.xlsx"
        # Create a workbook and add a worksheet
        workbook = xlsxwriter.Workbook(WRITE_FILE)
        worksheet = workbook.add_worksheet("findings")
        # Columns
        worksheet.set_default_row(25)
        worksheet.set_column(0, 0, 145)  # Resource ID.
        worksheet.set_column(1, 1, 15)  # Severity.
        worksheet.set_column(2, 2, 15)  # Impact.
        worksheet.set_column(3, 3, 105)  # Title.
        worksheet.set_column(4, 4, 15)  # Account ID.
        worksheet.set_column(5, 5, 15)  # Region.
        worksheet.set_column(6, 6, 25)  # Resource Type.
        worksheet.set_column(7, 7, 25)  # WorkflowStatus.
        worksheet.set_column(8, 8, 25)  # RecordState.
        worksheet.set_column(9, 9, 25)  # ComplianceStatus.
        # Formats
        title_format = workbook.add_format({"bold": True, "border": 1})
        raws_format = workbook.add_format({"text_wrap": True, "border": 1})
        critical_format = workbook.add_format({"bg_color": "#7d2105", "border": 1})
        high_format = workbook.add_format({"bg_color": "#ba2e0f", "border": 1})
        medium_format = workbook.add_format({"bg_color": "#cc6021", "border": 1})
        low_format = workbook.add_format({"bg_color": "#b49216", "border": 1})
        colums = [
            "Resource ID",
            "Severity",
            "Title",
            "AWS Account ID",
            "Region",
            "Resource Type",
            "WorkflowStatus",
            "RecordState",
            "ComplianceStatus",
        ]
        worksheet.write_row(
            0,
            0,
            colums
            + self.config_columns
            + self.tag_columns
            + self.account_columns
            + self.impact_columns,
            title_format,
        )
        # Iterate over the resources
        current_line = 1
        for resource, values in self.mh_findings.items():
            for finding in values["findings"]:
                for f, v in finding.items():
                    worksheet.write_row(current_line, 0, [resource], raws_format)
                    severity = v["SeverityLabel"]
                    if severity == "CRITICAL":
                        worksheet.write(current_line, 1, severity, critical_format)
                    elif severity == "HIGH":
                        worksheet.write(current_line, 1, severity, high_format)
                    elif severity == "MEDIUM":
                        worksheet.write(current_line, 1, severity, medium_format)
                    else:
                        worksheet.write(current_line, 1, severity, low_format)
                    tag_column_values = []
                    for column in self.tag_columns:
                        try:
                            tag_column_values.append(values["tags"][column])
                        except (KeyError, TypeError):
                            tag_column_values.append("")
                    config_column_values = []
                    for column in self.config_columns:
                        try:
                            config_column_values.append(values["config"][column])
                        except (KeyError, TypeError):
                            config_column_values.append("")
                    impact_column_values = []
                    for column in self.impact_columns:
                        try:
                            impact_column_values.append(values["impact"][column])
                        except (KeyError, TypeError):
                            impact_column_values.append("")
                    account_column_values = []
                    for column in self.account_columns:
                        try:
                            account_column_values.append(values["account"][column])
                        except (KeyError, TypeError):
                            account_column_values.append("")
                    row = (
                        [
                            f,
                            values.get("AwsAccountId", None),
                            values.get("Region", None),
                            values.get("ResourceType", None),
                            (
                                v.get("Workflow", {}).get("Status", None)
                                if v.get("Workflow")
                                else None
                            ),
                            v.get("RecordState", None),
                            (
                                v.get("Compliance", {}).get("Status", None)
                                if v.get("Compliance")
                                else None
                            ),
                        ]
                        # + impact_column_values
                        + account_column_values
                        + tag_column_values
                        + config_column_values
                    )
                    worksheet.write_row(current_line, 2, row)
                    current_line += 1
        workbook.close()
        print_table("XLSX:   ", WRITE_FILE, banners=self.banners)

    def generate_output_html(self):
        WRITE_FILE = f"{outputs_dir}metahub-{TIMESTRF}.html"
        templateLoader = jinja2.FileSystemLoader(searchpath="./")
        templateEnv = jinja2.Environment(loader=templateLoader, autoescape=True)
        TEMPLATE_FILE = "lib/html/template.html"
        template = templateEnv.get_template(TEMPLATE_FILE)
        # Convert Config to Boolean
        for resource_arn in self.mh_findings:
            keys_to_convert = ["config", "associations"]
            for key in keys_to_convert:
                if (
                    key in self.mh_findings[resource_arn]
                    and self.mh_findings[resource_arn][key]
                ):
                    for config in self.mh_findings[resource_arn][key]:
                        if bool(self.mh_findings[resource_arn][key][config]):
                            self.mh_findings[resource_arn][key][config] = True
                        else:
                            self.mh_findings[resource_arn][key][config] = False

        with open(WRITE_FILE, "w", encoding="utf-8") as f:
            html = template.render(
                data=self.mh_findings,
                statistics=self.mh_statistics,
                title="MetaHub",
                config_columns=self.config_columns,
                tag_columns=self.tag_columns,
                account_columns=self.account_columns,
                impact_columns=self.impact_columns,
                parameters=self.args,
            )
            f.write(html)

        print_table("HTML:  ", WRITE_FILE, banners=self.banners)

    def generate_output_rich(self):
        if self.banners:
            (
                severity_renderables,
                resource_type_renderables,
                workflows_renderables,
                region_renderables,
                accountid_renderables,
                recordstate_renderables,
                compliance_renderables,
            ) = generate_rich(self.mh_statistics)
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

    def show_results(self):
        print_table(
            "Total Findings: ",
            str(count_mh_findings(self.mh_findings)),
            banners=self.banners,
        )
        print_table(
            "Total Resources: ", str(len(self.mh_findings)), banners=self.banners
        )

    def list_findings(self):
        if self.mh_findings:
            for out in self.args.list_findings:
                print_title_line("List Findings: " + out, banners=self.banners)
                print(
                    json.dumps(
                        {
                            "short": self.mh_findings_short,
                            "inventory": self.mh_inventory,
                            "statistics": self.mh_statistics,
                            "full": self.mh_findings,
                        }[out],
                        indent=2,
                    )
                )


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
