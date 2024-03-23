from collections import defaultdict


def generate_statistics(mh_findings):
    root_level_statistics = {
        "ResourceId": defaultdict(int),
        "ResourceType": defaultdict(int),
        "Region": defaultdict(int),
        "AwsAccountId": defaultdict(int),
        "Title": defaultdict(int),
        "SeverityLabel": defaultdict(int),
        "RecordState": defaultdict(int),
        "ProductArn": defaultdict(int),
        "Workflow": defaultdict(int),
        "Compliance": defaultdict(int),
    }

    tags_statistics = defaultdict(lambda: defaultdict(int))
    config_statistics = defaultdict(lambda: {False: 0, True: 0})
    account_statistics = defaultdict(lambda: defaultdict(int))
    impact_statistics = defaultdict(lambda: defaultdict(int))
    score_groupped = {"red": 0, "orange": 0, "green": 0, "blue": 0}

    for resource_arn, resource_data in mh_findings.items():
        region = resource_data["Region"]
        aws_account_id = resource_data["AwsAccountId"]
        resource_type = resource_data["ResourceType"]

        for finding in resource_data["findings"]:
            for finding_title, findings_keys in finding.items():
                root_level_statistics["ResourceId"][resource_arn] += 1
                root_level_statistics["Title"][finding_title] += 1
                root_level_statistics["Region"][region] += 1
                root_level_statistics["AwsAccountId"][aws_account_id] += 1
                root_level_statistics["ResourceType"][resource_type] += 1

                for finding_key in findings_keys:
                    if finding_key in ("Id", "StandardsControlArn"):
                        continue
                    if finding_key == "Workflow" or finding_key == "Compliance":
                        try:
                            status = findings_keys[finding_key]["Status"]
                            root_level_statistics[finding_key][status] += 1
                        except TypeError:
                            pass
                        continue
                    root_level_statistics[finding_key][findings_keys[finding_key]] += 1

        if "tags" in resource_data and resource_data["tags"]:
            for finding in resource_data["findings"]:
                for tag, value in resource_data["tags"].items():
                    tags_statistics[tag][value] += 1

        if "config" in resource_data and resource_data["config"]:
            for finding in resource_data["findings"]:
                for check, value in resource_data["config"].items():
                    config_statistics[check][bool(value)] += 1

        if "account" in resource_data and resource_data["account"]:
            for finding in resource_data["findings"]:
                for tag, value in resource_data["account"].items():
                    if tag in ("AlternateContact", "Organizations"):
                        continue
                    account_statistics[tag][value] += 1

        if "impact" in resource_data and resource_data["impact"]:
            for finding in resource_data["findings"]:
                for check, value in resource_data["impact"].items():
                    value_key = [str(key) for key in value.keys()]
                    value = value_key[0]
                    if check == "score":
                        value = float(value)
                        if value >= 70:
                            score_groupped["red"] += 1
                        elif value < 70 and value > 10:
                            score_groupped["orange"] += 1
                        elif value < 10:
                            score_groupped["green"] += 1
                        else:
                            score_groupped["blue"] += 1
                    impact_statistics[check][value] += 1

    impact_statistics["score_groupped"] = score_groupped

    # Sort Statistics
    for key_to_sort in root_level_statistics:
        if key_to_sort not in ("tags", "config", "account", "impact"):
            root_level_statistics[key_to_sort] = dict(
                sorted(
                    root_level_statistics[key_to_sort].items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
            )

    return {
        **root_level_statistics,
        "tags": tags_statistics,
        "config": config_statistics,
        "account": account_statistics,
        "impact": impact_statistics,
    }
