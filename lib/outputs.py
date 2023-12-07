import csv
import json
from time import strftime

import jinja2
import xlsxwriter

from lib.config.configuration import outputs_dir, outputs_time_str
from lib.helpers import print_table

TIMESTRF = strftime(outputs_time_str)


def generate_output_json(
    mh_findings_short, mh_findings, mh_inventory, mh_statistics, json_mode, args
):
    WRITE_FILE = f"{outputs_dir}metahub-{json_mode}-{TIMESTRF}.json"
    with open(WRITE_FILE, "w", encoding="utf-8") as f:
        try:
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
        except ValueError as e:
            print("Error generating JSON Output (" + json_mode + "):", e)
    print_table("JSON (" + json_mode + "): ", WRITE_FILE, banners=args.banners)


def generate_output_csv(
    output, config_columns, tag_columns, account_columns, impact_columns, args
):
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
    print_table("CSV:   ", WRITE_FILE, banners=args.banners)


def generate_output_xlsx(
    output, config_columns, tag_columns, account_columns, impact_columns, args
):
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
    print_table("XLSX:   ", WRITE_FILE, banners=args.banners)


def generate_output_html(
    mh_findings,
    mh_statistics,
    config_columns,
    tag_columns,
    account_columns,
    impact_columns,
    args,
):
    WRITE_FILE = f"{outputs_dir}metahub-{TIMESTRF}.html"
    templateLoader = jinja2.FileSystemLoader(searchpath="./")
    templateEnv = jinja2.Environment(loader=templateLoader, autoescape=True)
    TEMPLATE_FILE = "lib/html/template.html"
    template = templateEnv.get_template(TEMPLATE_FILE)
    # Convert Config to Boolean
    for resource_arn in mh_findings:
        keys_to_convert = ["config", "associations"]
        for key in keys_to_convert:
            if key in mh_findings[resource_arn] and mh_findings[resource_arn][key]:
                for config in mh_findings[resource_arn][key]:
                    if bool(mh_findings[resource_arn][key][config]):
                        mh_findings[resource_arn][key][config] = True
                    else:
                        mh_findings[resource_arn][key][config] = False

    with open(WRITE_FILE, "w", encoding="utf-8") as f:
        html = template.render(
            data=mh_findings,
            statistics=mh_statistics,
            title="MetaHub",
            config_columns=config_columns,
            tag_columns=tag_columns,
            account_columns=account_columns,
            impact_columns=impact_columns,
            parameters=args,
        )
        f.write(html)

    print_table("HTML:  ", WRITE_FILE, banners=args.banners)


def generate_outputs(
    args, mh_findings_short, mh_inventory, mh_statistics, mh_findings, banners
):
    from lib.config.configuration import (
        account_columns,
        config_columns,
        impact_columns,
        tag_columns,
    )

    # Columns for CSV and HTML
    output_config_columns = (
        args.output_config_columns
        or config_columns
        or list(mh_statistics["config"].keys())
    )
    output_tag_columns = (
        args.output_tag_columns or tag_columns or list(mh_statistics["tags"].keys())
    )
    output_account_columns = (
        args.output_account_columns or account_columns or mh_statistics["account"]
    )
    output_impact_columns = impact_columns or mh_statistics["impact"]

    if mh_findings:
        for ouput_mode in args.output_modes:
            if ouput_mode.startswith("json"):
                json_mode = ouput_mode.split("-")[1]
                generate_output_json(
                    mh_findings_short,
                    mh_findings,
                    mh_inventory,
                    mh_statistics,
                    json_mode,
                    args,
                )
            if ouput_mode == "html":
                generate_output_html(
                    mh_findings,
                    mh_statistics,
                    output_config_columns,
                    output_tag_columns,
                    output_account_columns,
                    output_impact_columns,
                    args,
                )
            if ouput_mode == "csv":
                generate_output_csv(
                    mh_findings,
                    output_config_columns,
                    output_tag_columns,
                    output_account_columns,
                    output_impact_columns,
                    args,
                )
            if ouput_mode == "xlsx":
                generate_output_xlsx(
                    mh_findings,
                    output_config_columns,
                    output_tag_columns,
                    output_account_columns,
                    output_impact_columns,
                    args,
                )
