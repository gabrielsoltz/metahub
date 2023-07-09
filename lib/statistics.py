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
            if resource_arn not in root_level_statistics:
                root_level_statistics["ResourceId"][resource_arn] = 0
            root_level_statistics["ResourceId"][resource_arn] += 1
            region = mh_findings[resource_arn]["Region"]
            aws_account_id = mh_findings[resource_arn]["AwsAccountId"]
            resource_type = mh_findings[resource_arn]["ResourceType"]
            # Iterate Findings
            for finding in mh_findings[resource_arn]["findings"]:
                for finding_title, findings_keys in finding.items():
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

    def statistics_metatags(mh_findings_short):
        metatags_statistics = {}
        for resource_arn in mh_findings_short:
            if "metatags" in mh_findings_short[resource_arn]:
                if mh_findings_short[resource_arn]["metatags"]:
                    for finding in mh_findings_short[resource_arn]["findings"]:
                        for tag, value in mh_findings_short[resource_arn][
                            "metatags"
                        ].items():
                            if tag not in metatags_statistics:
                                metatags_statistics[tag] = {}
                            if value not in metatags_statistics[tag]:
                                metatags_statistics[tag][value] = 1
                            else:
                                metatags_statistics[tag][value] += 1
        return metatags_statistics

    def statistics_metachecks(mh_findings_short):
        metachecks_statistics = {}
        for resource_arn in mh_findings_short:
            if "metachecks" in mh_findings_short[resource_arn]:
                if mh_findings_short[resource_arn]["metachecks"]:
                    for finding in mh_findings_short[resource_arn]["findings"]:
                        for check, value in mh_findings_short[resource_arn][
                            "metachecks"
                        ].items():
                            if check not in metachecks_statistics:
                                metachecks_statistics[check] = {False: 0, True: 0}
                            if bool(
                                mh_findings_short[resource_arn]["metachecks"][check]
                            ):
                                metachecks_statistics[check][True] += 1
                            else:
                                metachecks_statistics[check][False] += 1
        return metachecks_statistics

    def statistics_metaaccount(mh_findings_short):
        metaaccount_statistics = {}
        for resource_arn in mh_findings_short:
            if "metaaccount" in mh_findings_short[resource_arn]:
                if mh_findings_short[resource_arn]["metaaccount"]:
                    for finding in mh_findings_short[resource_arn]["findings"]:
                        for tag, value in mh_findings_short[resource_arn][
                            "metaaccount"
                        ].items():
                            if tag == "AlternateContact":
                                continue
                            if tag not in metaaccount_statistics:
                                metaaccount_statistics[tag] = {}
                            if value not in metaaccount_statistics[tag]:
                                metaaccount_statistics[tag][value] = 1
                            else:
                                metaaccount_statistics[tag][value] += 1
        return metaaccount_statistics

    mh_statistics = statistics_findings(mh_findings)
    mh_statistics["metatags"] = statistics_metatags(mh_findings)
    mh_statistics["metachecks"] = statistics_metachecks(mh_findings)
    mh_statistics["metaaccount"] = statistics_metaaccount(mh_findings)

    # Sort Statistics
    for key_to_sort in mh_statistics:
        if key_to_sort not in ("metatags", "metachecks", "metaaccount"):
            mh_statistics[key_to_sort] = dict(
                sorted(
                    mh_statistics[key_to_sort].items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
            )

    return mh_statistics
