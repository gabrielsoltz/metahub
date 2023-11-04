import csv
import json

import jinja2
import xlsxwriter


def generate_output_json(
    mh_findings_short, mh_findings, mh_inventory, mh_statistics, json_mode, f
):
    json.dump(
        {
            "short": mh_findings_short,
            "full": mh_findings,
            "inventory": mh_inventory,
            "statistics": mh_statistics,
        }[json_mode],
        f,
        indent=2,
    )


def generate_output_csv(
    output, config_columns, tag_columns, account_columns, impact_columns, csv_file
):
    with open(csv_file, "w", encoding="utf-8", newline="") as output_file:
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
            colums + config_columns + tag_columns + account_columns + impact_columns
        )
        dict_writer = csv.DictWriter(output_file, fieldnames=colums)
        dict_writer.writeheader()
        # Iterate over the resources
        for resource, values in output.items():
            for finding in values["findings"]:
                for f, v in finding.items():
                    tag_column_values = []
                    for column in tag_columns:
                        try:
                            tag_column_values.append(values["tags"][column])
                        except (KeyError, TypeError):
                            tag_column_values.append("")
                    config_column_values = []
                    for column in config_columns:
                        try:
                            config_column_values.append(values["config"][column])
                        except (KeyError, TypeError):
                            config_column_values.append("")
                    impact_column_values = []
                    for column in impact_columns:
                        try:
                            impact_column_values.append(values["impact"][column])
                        except (KeyError, TypeError):
                            impact_column_values.append("")
                    account_column_values = []
                    for column in account_columns:
                        try:
                            account_column_values.append(values["account"][column])
                        except (KeyError, TypeError):
                            account_column_values.append("")
                    row = (
                        [
                            resource,
                            v.get("SeverityLabel", None),
                            values.get("impact", None).get("Impact", None)
                            if values.get("impact")
                            else None,
                            f,
                            values.get("AwsAccountId", None),
                            values.get("Region", None),
                            values.get("ResourceType", None),
                            v.get("Workflow", {}).get("Status", None)
                            if v.get("Workflow")
                            else None,
                            v.get("RecordState", None),
                            v.get("Compliance", {}).get("Status", None)
                            if v.get("Compliance")
                            else None,
                        ]
                        # + impact_column_values
                        + account_column_values
                        + tag_column_values
                        + config_column_values
                    )
                    dict_writer.writerow(dict(zip(colums, row)))


def generate_output_xlsx(
    output, config_columns, tag_columns, account_columns, impact_columns, xlsx_file
):
    # Create a workbook and add a worksheet
    workbook = xlsxwriter.Workbook(xlsx_file)
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
        colums + config_columns + tag_columns + account_columns + impact_columns,
        title_format,
    )
    # Iterate over the resources
    current_line = 1
    for resource, values in output.items():
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
                for column in tag_columns:
                    try:
                        tag_column_values.append(values["tags"][column])
                    except (KeyError, TypeError):
                        tag_column_values.append("")
                config_column_values = []
                for column in config_columns:
                    try:
                        config_column_values.append(values["config"][column])
                    except (KeyError, TypeError):
                        config_column_values.append("")
                impact_column_values = []
                for column in impact_columns:
                    try:
                        impact_column_values.append(values["impact"][column])
                    except (KeyError, TypeError):
                        impact_column_values.append("")
                account_column_values = []
                for column in account_columns:
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
                        v.get("Workflow", {}).get("Status", None)
                        if v.get("Workflow")
                        else None,
                        v.get("RecordState", None),
                        v.get("Compliance", {}).get("Status", None)
                        if v.get("Compliance")
                        else None,
                    ]
                    # + impact_column_values
                    + account_column_values
                    + tag_column_values
                    + config_column_values
                )
                worksheet.write_row(current_line, 2, row)
                current_line += 1
    workbook.close()


def generate_output_html(
    mh_findings,
    mh_statistics,
    config_columns,
    tag_columns,
    account_columns,
    impact_columns,
):
    templateLoader = jinja2.FileSystemLoader(searchpath="./")
    templateEnv = jinja2.Environment(loader=templateLoader, autoescape=True)
    TEMPLATE_FILE = "lib/html/template.html"
    template = templateEnv.get_template(TEMPLATE_FILE)
    # Convert Config to Boolean
    for resource_arn in mh_findings:
        if (
            "config" in mh_findings[resource_arn]
            and mh_findings[resource_arn]["config"]
        ):
            for config in mh_findings[resource_arn]["config"]:
                if bool(mh_findings[resource_arn]["config"][config]):
                    mh_findings[resource_arn]["config"][config] = True
                else:
                    mh_findings[resource_arn]["config"][config] = False
    html = template.render(
        data=mh_findings,
        statistics=mh_statistics,
        title="MetaHub",
        config_columns=config_columns,
        tag_columns=tag_columns,
        account_columns=account_columns,
        impact_columns=impact_columns,
    )
    return html
