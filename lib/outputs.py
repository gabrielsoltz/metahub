import csv
import json
import sqlite3
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
        self.__logger = logger
        self.__mh_findings = mh_findings
        self.__mh_findings_short = mh_findings_short
        self.__mh_inventory = mh_inventory
        self.__mh_statistics = mh_statistics
        self.__banners = args.banners
        self.__args = args
        # Output Columns
        self.__default_columns = [
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
        self.__config_columns = (
            args.output_config_columns
            or config_columns
            or list(mh_statistics["config"].keys())
        )
        self.__tag_columns = (
            args.output_tag_columns or tag_columns or list(mh_statistics["tags"].keys())
        )
        self.__account_columns = (
            args.output_account_columns or account_columns or mh_statistics["account"]
        )
        self.__impact_columns = impact_columns or mh_statistics["impact"]

    def generate_outputs(self):
        if self.__mh_findings:
            for output_mode in self.__args.output_modes:
                if output_mode.startswith("json"):
                    json_mode = output_mode.split("-")[1]
                    self.generate_output_json(json_mode)
                elif output_mode == "csv":
                    self.generate_output_csv()
                elif output_mode == "xlsx":
                    self.generate_output_xlsx()
                elif output_mode == "html":
                    self.generate_output_html()
                elif output_mode == "sqlite":
                    self.generate_output_sqlite()

    def generate_output_json(self, json_mode):
        WRITE_FILE = f"{outputs_dir}metahub-{json_mode}-{TIMESTRF}.json"
        try:
            with open(WRITE_FILE, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "short": self.__mh_findings_short,
                        "full": self.__mh_findings,
                        "inventory": self.__mh_inventory,
                        "statistics": self.__mh_statistics,
                    }[json_mode],
                    f,
                    indent=2,
                )
        except ValueError as e:
            raise Exception(f"Error generating JSON Output ({json_mode}): {e}")
        print_table("JSON (" + json_mode + "): ", WRITE_FILE, banners=self.__banners)

    def generate_output_csv(self):
        WRITE_FILE = f"{outputs_dir}metahub-{TIMESTRF}.csv"
        with open(WRITE_FILE, "w", encoding="utf-8", newline="") as output_file:
            columns = self.__default_columns
            columns += (
                self.__config_columns
                + self.__tag_columns
                + self.__account_columns
                + self.__impact_columns
            )
            dict_writer = csv.DictWriter(output_file, fieldnames=columns)
            dict_writer.writeheader()
            # Iterate over the resources
            for resource, values in self.__mh_findings.items():
                for finding in values["findings"]:
                    for f, v in finding.items():
                        tag_column_values = [
                            (
                                values.get("tags", {}).get(column, "")
                                if values.get("tags")
                                else ""
                            )
                            for column in self.__tag_columns
                        ]
                        config_column_values = [
                            (
                                values.get("config", {}).get(column, "")
                                if values.get("config")
                                else ""
                            )
                            for column in self.__config_columns
                        ]
                        account_column_values = [
                            (
                                values.get("account", {}).get(column, "")
                                if values.get("account")
                                else ""
                            )
                            for column in self.__account_columns
                        ]
                        impact_column_values = [
                            list(values.get("impact", {}).get(column, ""))[0]
                            for column in self.__impact_columns
                        ]
                        row = (
                            [
                                resource,
                                v.get("SeverityLabel", None),
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
                            + config_column_values
                            + tag_column_values
                            + account_column_values
                            + impact_column_values
                        )
                        dict_writer.writerow(dict(zip(columns, row)))
        print_table("CSV:   ", WRITE_FILE, banners=self.__banners)

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
        columns = self.__default_columns
        columns += (
            self.__config_columns
            + self.__tag_columns
            + self.__account_columns
            + self.__impact_columns
        )
        worksheet.write_row(0, 0, columns, title_format)
        # Iterate over the resources
        current_line = 1
        for resource, values in self.__mh_findings.items():
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
                    tag_column_values = [
                        (
                            values.get("tags", {}).get(column, "")
                            if values.get("tags")
                            else ""
                        )
                        for column in self.__tag_columns
                    ]
                    config_column_values = [
                        (
                            values.get("config", {}).get(column, "")
                            if values.get("config")
                            else ""
                        )
                        for column in self.__config_columns
                    ]
                    account_column_values = [
                        (
                            values.get("account", {}).get(column, "")
                            if values.get("account")
                            else ""
                        )
                        for column in self.__account_columns
                    ]
                    impact_column_values = [
                        list(values.get("impact", {}).get(column, ""))[0]
                        for column in self.__impact_columns
                    ]
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
                        + config_column_values
                        + tag_column_values
                        + account_column_values
                        + impact_column_values
                    )
                    worksheet.write_row(current_line, 2, row)
                    current_line += 1
        workbook.close()
        print_table("XLSX:   ", WRITE_FILE, banners=self.__banners)

    def generate_output_html(self):
        WRITE_FILE = f"{outputs_dir}metahub-{TIMESTRF}.html"
        templateLoader = jinja2.FileSystemLoader(searchpath="./")
        templateEnv = jinja2.Environment(loader=templateLoader, autoescape=True)
        TEMPLATE_FILE = "lib/html/template.html"
        template = templateEnv.get_template(TEMPLATE_FILE)
        # Convert Config to Boolean
        for resource_arn in self.__mh_findings:
            keys_to_convert = ["config", "associations"]
            for key in keys_to_convert:
                if (
                    key in self.__mh_findings[resource_arn]
                    and self.__mh_findings[resource_arn][key]
                ):
                    for config in self.__mh_findings[resource_arn][key]:
                        if bool(self.__mh_findings[resource_arn][key][config]):
                            self.__mh_findings[resource_arn][key][config] = True
                        else:
                            self.__mh_findings[resource_arn][key][config] = False

        with open(WRITE_FILE, "w", encoding="utf-8") as f:
            html = template.render(
                data=self.__mh_findings,
                statistics=self.__mh_statistics,
                title="MetaHub",
                config_columns=self.__config_columns,
                tag_columns=self.__tag_columns,
                account_columns=self.__account_columns,
                impact_columns=self.__impact_columns,
                parameters=self.__args,
            )
            f.write(html)

        print_table("HTML:  ", WRITE_FILE, banners=self.__banners)

    def generate_output_rich(self):
        if self.__banners:
            (
                severity_renderables,
                resource_type_renderables,
                workflows_renderables,
                region_renderables,
                accountid_renderables,
                recordstate_renderables,
                compliance_renderables,
            ) = generate_rich(self.__mh_statistics)
            console = Console()
            print_color("Severities:")
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
            str(count_mh_findings(self.__mh_findings)),
            banners=self.__banners,
        )
        print_table(
            "Total Resources: ", str(len(self.__mh_findings)), banners=self.__banners
        )

    def list_findings(self):
        if self.__mh_findings:
            for out in self.__args.list_findings:
                print_title_line("List Findings: " + out, banners=self.__banners)
                print(
                    json.dumps(
                        {
                            "short": self.__mh_findings_short,
                            "inventory": self.__mh_inventory,
                            "statistics": self.__mh_statistics,
                            "full": self.__mh_findings,
                        }[out],
                        indent=2,
                    )
                )

    def generate_output_sqlite(self):
        WRITE_FILE = f"{outputs_dir}metahub-{TIMESTRF}.db"
        conn = sqlite3.connect(WRITE_FILE)
        cursor = conn.cursor()

        def create_table(cursor, table_definition):
            cursor.execute(table_definition)

        resources_table = """
        CREATE TABLE IF NOT EXISTS resources (
            resource_arn VARCHAR PRIMARY KEY,
            resource_type VARCHAR,
            resource_region VARCHAR,
            resource_account_id VARCHAR,
            resource_account_alias VARCHAR,
            resource_tags TEXT,
            resource_exposure VARCHAR,
            resource_access VARCHAR,
            resource_encryption VARCHAR,
            resource_status VARCHAR,
            resource_application VARCHAR,
            resource_environment VARCHAR,
            resource_owner VARCHAR,
            resource_score INTEGER,
            resource_findings_score INTEGER,
            resource_findings_critical INTEGER,
            resource_findings_high INTEGER,
            resource_findings_medium INTEGER,
            resource_findings_low INTEGER,
            resource_findings_informational INTEGER,
            FOREIGN KEY (resource_account_id) REFERENCES accounts(account_id)
        )
        """

        findings_table = """
        CREATE TABLE IF NOT EXISTS findings (
            finding_id VARCHAR PRIMARY KEY,
            finding_title VARCHAR,
            finding_severity VARCHAR,
            finding_workflowstatus VARCHAR,
            finding_recordstate VARCHAR,
            finding_compliancestatus VARCHAR,
            finding_productarn VARCHAR,
            finding_resource_arn VARCHAR
        )
        """

        accounts_table = """
        CREATE TABLE IF NOT EXISTS accounts (
            account_id INTEGER PRIMARY KEY,
            account_alias VARCHAR,
            account_organizations_id VARCHAR,
            account_organizations_arn VARCHAR,
            account_master_account_id VARCHAR,
            account_master_account_email VARCHAR,
            account_alternate_contact_type VARCHAR,
            account_alternate_contact_name VARCHAR,
            account_alternate_contact_email VARCHAR,
            account_alternate_contact_phone VARCHAR,
            account_alternate_contact_title VARCHAR
        )
        """

        create_table(cursor, resources_table)
        create_table(cursor, findings_table)
        create_table(cursor, accounts_table)

        INSERT_RESOURCES = """INSERT INTO resources (resource_arn, resource_type, resource_region, resource_account_id, resource_account_alias, resource_tags, resource_exposure, resource_access, resource_encryption, resource_status, resource_application, resource_environment, resource_owner, resource_score, resource_findings_score, resource_findings_critical, resource_findings_high, resource_findings_medium, resource_findings_low, resource_findings_informational)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

        INSERT_FINDINGS = """INSERT INTO findings (finding_id, finding_title, finding_severity, finding_workflowstatus, finding_recordstate, finding_compliancestatus, finding_productarn, finding_resource_arn)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""

        INSERT_ACCOUNTS = """INSERT INTO accounts (account_id, account_alias, account_organizations_id, account_organizations_arn, account_master_account_id, account_master_account_email, account_alternate_contact_type, account_alternate_contact_name, account_alternate_contact_email, account_alternate_contact_phone, account_alternate_contact_title)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

        CREATE_INDEX_FINDINGS_RESOURCE_ARN = """CREATE INDEX IF NOT EXISTS idx_findings_finding_resource_arn ON findings (finding_resource_arn)"""
        CREATE_INDEX_FINDINGS_FINDING_ID = """CREATE INDEX IF NOT EXISTS idx_findings_finding_id ON findings (finding_id)"""

        for resource_arn, data in self.__mh_findings.items():
            resource_type = data["ResourceType"]
            resource_region = data["Region"]
            account_id = data["AwsAccountId"]
            resource_tags = json.dumps(data["tags"])
            # resource_config = json.dumps(data["config"])
            # resource_cloudtrail = json.dumps(data["cloudtrail"])
            resource_exposure = list(data["impact"]["exposure"].keys())[0]
            resource_access = list(data["impact"]["access"].keys())[0]
            resource_encryption = list(data["impact"]["encryption"].keys())[0]
            resource_status = list(data["impact"]["status"].keys())[0]
            resource_application = list(data["impact"]["application"].keys())[0]
            resource_environment = list(data["impact"]["environment"].keys())[0]
            resource_owner = list(data["impact"]["owner"].keys())[0]
            resource_score = list(data["impact"]["score"].keys())[0]
            for score, findings in data["impact"]["findings"].items():
                resource_findings_score = score
                resource_findings_critical = findings["findings"]["CRITICAL"]
                resource_findings_high = findings["findings"]["HIGH"]
                resource_findings_medium = findings["findings"]["MEDIUM"]
                resource_findings_low = findings["findings"]["LOW"]
                resource_findings_informational = findings["findings"]["INFORMATIONAL"]
            if data.get("account", {}):
                account_alias = data.get("account", {})["Alias"]
                account_organization = data.get("account", {}).get("Organizations", {})
                if account_organization:
                    account_organization_id = account_organization.get("Id")
                    account_organization_arn = account_organization.get("Arn")
                    account_master_account_id = account_organization.get(
                        "MasterAccountId"
                    )
                    account_master_account_email = account_organization.get(
                        "MasterAccountEmail"
                    )
                else:
                    account_organization_id = ""
                    account_organization_arn = ""
                    account_master_account_id = ""
                    account_master_account_email = ""
                account_alternate_contact_type = (
                    data.get("account", {})
                    .get("AlternateContact", {})
                    .get("AlternateContactType")
                )
                account_alternate_contact_name = (
                    data.get("account", {}).get("AlternateContact", {}).get("Name")
                )
                account_alternate_contact_email = (
                    data.get("account", {})
                    .get("AlternateContact", {})
                    .get("EmailAddress")
                )
                account_alternate_contact_phone = (
                    data.get("account", {})
                    .get("AlternateContact", {})
                    .get("PhoneNumber")
                )
                account_alternate_contact_title = (
                    data.get("account", {}).get("AlternateContact", {}).get("Title")
                )
            else:
                account_alias = ""
                account_organization_id = ""
                account_organization_arn = ""
                account_master_account_id = ""
                account_master_account_email = ""
                account_alternate_contact_type = ""
                account_alternate_contact_name = ""
                account_alternate_contact_email = ""
                account_alternate_contact_phone = ""
                account_alternate_contact_title = ""
            cursor.execute(
                INSERT_RESOURCES,
                (
                    resource_arn,
                    resource_type,
                    resource_region,
                    account_id,
                    account_alias,
                    resource_tags,
                    resource_exposure,
                    resource_access,
                    resource_encryption,
                    resource_status,
                    resource_application,
                    resource_environment,
                    resource_owner,
                    resource_score,
                    resource_findings_score,
                    resource_findings_critical,
                    resource_findings_high,
                    resource_findings_medium,
                    resource_findings_low,
                    resource_findings_informational,
                ),
            )
            for finding in data["findings"]:
                for finding_title, values in finding.items():
                    finding_id = values["Id"]
                    finding_severity = values["SeverityLabel"]
                    finding_workflowstatus = values["Workflow"]["Status"]
                    finding_recordstate = values["RecordState"]
                    finding_compliancestatus = values["Compliance"]["Status"]
                    finding_productarn = values["ProductArn"]
                    try:
                        cursor.execute(
                            INSERT_FINDINGS,
                            (
                                finding_id,
                                finding_title,
                                finding_severity,
                                finding_workflowstatus,
                                finding_recordstate,
                                finding_compliancestatus,
                                finding_productarn,
                                resource_arn,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        # If there's an integrity error (likely due to violating UNIQUE constraint), just continue to the next entry
                        continue
            try:
                cursor.execute(
                    INSERT_ACCOUNTS,
                    (
                        account_id,
                        account_alias,
                        account_organization_id,
                        account_organization_arn,
                        account_master_account_id,
                        account_master_account_email,
                        account_alternate_contact_type,
                        account_alternate_contact_name,
                        account_alternate_contact_email,
                        account_alternate_contact_phone,
                        account_alternate_contact_title,
                    ),
                )
            except sqlite3.IntegrityError:
                # If there's an integrity error (likely due to violating UNIQUE constraint), just continue to the next entry
                continue

        cursor.execute(CREATE_INDEX_FINDINGS_RESOURCE_ARN)
        cursor.execute(CREATE_INDEX_FINDINGS_FINDING_ID)

        conn.commit()
        conn.close()
        print_table("SQLite: ", WRITE_FILE, banners=self.__banners)


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
