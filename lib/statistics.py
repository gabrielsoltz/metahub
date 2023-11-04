def generate_statistics(mh_findings):
    def statistics_findings(mh_findings):
        root_level_statistics = {
            "ResourceId": {},
            "ResourceType": {},
            "Region": {},
            "AwsAccountId": {},
            "Title": {},
            "SeverityLabel": {},
            "RecordState": {},
            "ProductArn": {},
            "Workflow": {},
            "Compliance": {},
        }
        # Iterate Resources
        for resource_arn in mh_findings:
            region = mh_findings[resource_arn]["Region"]
            aws_account_id = mh_findings[resource_arn]["AwsAccountId"]
            resource_type = mh_findings[resource_arn]["ResourceType"]
            # Iterate Findings
            for finding in mh_findings[resource_arn]["findings"]:
                for finding_title, findings_keys in finding.items():
                    if resource_arn not in root_level_statistics["ResourceId"]:
                        root_level_statistics["ResourceId"][resource_arn] = 0
                    root_level_statistics["ResourceId"][resource_arn] += 1
                    if finding_title not in root_level_statistics["Title"]:
                        root_level_statistics["Title"][finding_title] = 0
                    root_level_statistics["Title"][finding_title] += 1
                    if region not in root_level_statistics["Region"]:
                        root_level_statistics["Region"][region] = 0
                    root_level_statistics["Region"][region] += 1
                    if aws_account_id not in root_level_statistics["AwsAccountId"]:
                        root_level_statistics["AwsAccountId"][aws_account_id] = 0
                    root_level_statistics["AwsAccountId"][aws_account_id] += 1
                    if resource_type not in root_level_statistics["ResourceType"]:
                        root_level_statistics["ResourceType"][resource_type] = 0
                    root_level_statistics["ResourceType"][resource_type] += 1
                    # Iterate Finding Keys and Values (e.g. "Workflow", "Compliance")
                    for finding_key in findings_keys:
                        if finding_key in ("Id", "StandardsControlArn"):
                            continue
                        if finding_key == "Workflow" or finding_key == "Compliance":
                            try:
                                if (
                                    findings_keys[finding_key]["Status"]
                                    not in root_level_statistics[finding_key]
                                ):
                                    root_level_statistics[finding_key][
                                        findings_keys[finding_key]["Status"]
                                    ] = 0
                                root_level_statistics[finding_key][
                                    findings_keys[finding_key]["Status"]
                                ] += 1
                            except TypeError:
                                pass
                            continue
                        if (
                            findings_keys[finding_key]
                            not in root_level_statistics[finding_key]
                        ):
                            root_level_statistics[finding_key][
                                findings_keys[finding_key]
                            ] = 0
                        root_level_statistics[finding_key][
                            findings_keys[finding_key]
                        ] += 1

        return root_level_statistics

    def statistics_tags(mh_findings_short):
        tags_statistics = {}
        for resource_arn in mh_findings_short:
            if "tags" in mh_findings_short[resource_arn]:
                if mh_findings_short[resource_arn]["tags"]:
                    for finding in mh_findings_short[resource_arn]["findings"]:
                        for tag, value in mh_findings_short[resource_arn][
                            "tags"
                        ].items():
                            if tag not in tags_statistics:
                                tags_statistics[tag] = {}
                            if value not in tags_statistics[tag]:
                                tags_statistics[tag][value] = 1
                            else:
                                tags_statistics[tag][value] += 1
        return tags_statistics

    def statistics_config(mh_findings_short):
        config_statistics = {}
        for resource_arn in mh_findings_short:
            if "config" in mh_findings_short[resource_arn]:
                if mh_findings_short[resource_arn]["config"]:
                    for finding in mh_findings_short[resource_arn]["findings"]:
                        for check, value in mh_findings_short[resource_arn][
                            "config"
                        ].items():
                            if check not in config_statistics:
                                config_statistics[check] = {False: 0, True: 0}
                            if bool(mh_findings_short[resource_arn]["config"][check]):
                                config_statistics[check][True] += 1
                            else:
                                config_statistics[check][False] += 1
        return config_statistics

    def statistics_account(mh_findings_short):
        account_statistics = {}
        for resource_arn in mh_findings_short:
            if "account" in mh_findings_short[resource_arn]:
                if mh_findings_short[resource_arn]["account"]:
                    for finding in mh_findings_short[resource_arn]["findings"]:
                        for tag, value in mh_findings_short[resource_arn][
                            "account"
                        ].items():
                            if tag == "AlternateContact":
                                continue
                            if tag not in account_statistics:
                                account_statistics[tag] = {}
                            if value not in account_statistics[tag]:
                                account_statistics[tag][value] = 1
                            else:
                                account_statistics[tag][value] += 1
        return account_statistics

    def statistics_impact(mh_findings_short):
        impact_statistics = {}
        for resource_arn in mh_findings_short:
            if "impact" in mh_findings_short[resource_arn]:
                if mh_findings_short[resource_arn]["impact"]:
                    for finding in mh_findings_short[resource_arn]["findings"]:
                        for check, value in mh_findings_short[resource_arn][
                            "impact"
                        ].items():
                            if check not in impact_statistics:
                                impact_statistics[check] = {False: 0, True: 0}
                            if bool(mh_findings_short[resource_arn]["impact"][check]):
                                impact_statistics[check][True] += 1
                            else:
                                impact_statistics[check][False] += 1
        return impact_statistics

    mh_statistics = statistics_findings(mh_findings)
    mh_statistics["tags"] = statistics_tags(mh_findings)
    mh_statistics["config"] = statistics_config(mh_findings)
    mh_statistics["account"] = statistics_account(mh_findings)
    mh_statistics["impact"] = statistics_impact(mh_findings)

    # Sort Statistics
    for key_to_sort in mh_statistics:
        if key_to_sort not in ("tags", "config", "account"):
            mh_statistics[key_to_sort] = dict(
                sorted(
                    mh_statistics[key_to_sort].items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
            )

    return mh_statistics
