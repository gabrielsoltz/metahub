"""Integration AWS Security Hub"""
from sys import exit

from alive_progress import alive_bar
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError

from lib.AwsHelpers import assume_role, get_boto3_client
from lib.config.configuration import sh_enrich_with


class SecurityHub:
    """Interfaces with the AWS Security Hub"""

    def __init__(
        self, logger, sh_region, sh_account=False, sh_role=False, sh_profile=False
    ):
        self.logger = logger
        if sh_role and sh_account:
            shsess = assume_role(logger, sh_account, sh_role)
        else:
            shsess = None
        self.sh_client = get_boto3_client(
            self.logger, "securityhub", sh_region, shsess, sh_profile
        )
        region_aggregator = self.get_region_aggregator()
        if region_aggregator != sh_region:
            logger.warning(
                "You are using region %s, but your findings aggregator is in region: %s. Use --sh-region %s for aggregated findings...",
                sh_region,
                region_aggregator,
                region_aggregator,
            )

    def get_region_aggregator(self):
        try:
            sh_findings_aggregator = self.sh_client.list_finding_aggregators()[
                "FindingAggregators"
            ]
        except (EndpointConnectionError, Exception) as e:
            self.logger.error("Error getting SecurityHub aggregators: {}".format(e))
            sh_findings_aggregator = False
        if sh_findings_aggregator:
            sh_findings_aggregator_region = sh_findings_aggregator[0][
                "FindingAggregatorArn"
            ].split(":")[3]
            return sh_findings_aggregator_region
        return False

    def get_findings(self, sh_filters):
        """Get Security Findings from Security Hub with Filters applied"""
        self.logger.info("Gathering SecurityHub findings...")

        findings = []
        next_token = ""

        with alive_bar(
            title="-> Gathering findings from Security Hub..."
        ) as bar:  # Initialize the progress bar
            while True:
                try:
                    response = self.sh_client.get_findings(
                        Filters=sh_filters,
                        NextToken=next_token,
                        # The maximum value is 100 as per AWS documentation
                        MaxResults=100,
                    )
                    # Add findings to the list
                    findings.extend(response["Findings"])
                    bar(
                        len(response["Findings"])
                    )  # Update the progress bar by the number of new findings
                except (ClientError, BotoCoreError) as err:
                    self.logger.error(
                        "An error occurred when attempting to gather SecurityHub data: %s. Try using --sh-account, --sh-assume-role and --sh-region to specify the SecurityHub account and region.",
                        err,
                    )
                    # No point proceeding without the data
                    exit(1)
                if "Findings" not in list(response.keys()):
                    self.logger.error(
                        "get_findings returned unexpected data (No 'Findings' key) - %s",
                        str(response),
                    )
                    exit(1)
                if "NextToken" in list(response.keys()):
                    next_token = response["NextToken"]
                    self.logger.info("Found a token, gathering more results")
                else:
                    break

        self.logger.info("Gathering SecurityHub results complete")
        return findings

    def _spit_list(self, lst, n):
        """split a list into multipe lists from n items"""
        for i in range(0, len(lst), n):
            yield lst[i : i + n]

    def update_findings_workflow(self, mh_findings, update):
        update["FindingIdentifiers"] = []
        response_multiple = []
        for mh_finding in mh_findings:
            for finding in mh_findings[mh_finding]["findings"]:
                for f, v in finding.items():
                    FindingIdentifier = {"Id": v["Id"], "ProductArn": v["ProductArn"]}
                    update["FindingIdentifiers"].append(FindingIdentifier)
        self.logger.info("Splitting findings into 100 items batches...")
        sub_list_count = 0
        for FindingIdentifiers_sub_list in list(
            self._spit_list(update["FindingIdentifiers"], 100)
        ):
            sub_list_count += 1
            self.logger.info(
                "Updating Batch %s (items: %s)",
                sub_list_count,
                len(FindingIdentifiers_sub_list),
            )
            response = self.sh_client.batch_update_findings(
                FindingIdentifiers=FindingIdentifiers_sub_list,
                Workflow=update["Workflow"],
                Note=update["Note"],
            )
            response_multiple.append(response)
        return response_multiple

    def update_findings_meta(self, mh_findings):
        response_multiple = []
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
            # Keep only impact keys
            if (
                "impact" in mh_findings[resource_arn]
                and mh_findings[resource_arn]["impact"]
            ):
                for impact_key, impact_value in mh_findings[resource_arn][
                    "impact"
                ].items():
                    if impact_value:
                        for impact in impact_value.keys():
                            mh_findings[resource_arn]["impact"][impact_key] = impact

        for mh_finding in mh_findings:
            values_to_enrich = {}
            for c in sh_enrich_with:
                try:
                    values = mh_findings[mh_finding][c]
                    if not values:
                        values = {}
                except KeyError:
                    values = {}
                for key in list(values):
                    values[key] = str(values[key])
                values_to_enrich.update(values)

            for finding in mh_findings[mh_finding]["findings"]:
                for f, v in finding.items():
                    FindingIdentifier = {"Id": v["Id"], "ProductArn": v["ProductArn"]}
                # To Do: Improve, only one update for resource.
                if values_to_enrich:
                    criticality = int(float(values_to_enrich["score"]))
                    self.logger.info(
                        "Enriching finding %s with Context: %s",
                        FindingIdentifier["Id"],
                        values_to_enrich,
                    )
                    response = self.sh_client.batch_update_findings(
                        FindingIdentifiers=[FindingIdentifier],
                        UserDefinedFields=values_to_enrich,
                        Criticality=criticality,
                        Note={"Text": "Enriching Findings", "UpdatedBy": "MetaHub"},
                    )
                    response_multiple.append(response)
                else:
                    self.logger.info(
                        "Ignoring finding %s as it has not Context",
                        FindingIdentifier["Id"],
                    )
        return response_multiple


def parse_finding(finding):
    """Returns resource ARN and finding parsed for it"""
    findings = {
        finding["Title"]: {
            "SeverityLabel": finding["Severity"]["Label"],
            "Workflow": finding.get("Workflow"),
            "RecordState": finding["RecordState"],
            "Compliance": finding.get("Compliance"),
            "Id": finding.get("Id"),
            "ProductArn": finding.get("ProductArn"),
            "StandardsControlArn": finding.get("ProductFields").get(
                "StandardsControlArn"
            ),
        },
    }
    return finding["Resources"][0]["Id"], findings


def set_sh_filters(sh_filters):
    """Return filters for AWS Security Hub get_findings Call"""
    filters = {}
    for key, values in sh_filters.items():
        if key != "self" and values is not None:
            filters[key] = []
            for value in values:
                value_to_append = {"Comparison": "EQUALS", "Value": value}
                filters[key].append(value_to_append)
    return filters
