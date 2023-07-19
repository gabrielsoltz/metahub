"""Integration AWS Security Hub"""
from sys import exit

import boto3
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError

from lib.AwsHelpers import assume_role, get_boto3_client


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
        # Convert metachecks to booleans
        for resource_arn in mh_findings:
            if (
                "metachecks" in mh_findings[resource_arn]
                and mh_findings[resource_arn]["metachecks"]
            ):
                for metacheck in mh_findings[resource_arn]["metachecks"]:
                    if bool(mh_findings[resource_arn]["metachecks"][metacheck]):
                        mh_findings[resource_arn]["metachecks"][metacheck] = True
                    else:
                        mh_findings[resource_arn]["metachecks"][metacheck] = False
        for mh_finding in mh_findings:
            # MetaTags
            try:
                finding_metatags = mh_findings[mh_finding]["metatags"]
                if not finding_metatags:
                    finding_metatags = {}
            except KeyError:
                finding_metatags = {}
            for key in list(finding_metatags):
                finding_metatags[key] = str(finding_metatags[key])
            # MetaChecks
            try:
                finding_metachecks = mh_findings[mh_finding]["metachecks"]
                if not finding_metachecks:
                    finding_metachecks = {}
            except KeyError:
                finding_metachecks = {}
            for key in list(finding_metachecks):
                finding_metachecks[key] = str(finding_metachecks[key])
            # MetaAccount
            try:
                finding_metaaccount = mh_findings[mh_finding]["metaaccount"]
                if not finding_metaaccount:
                    finding_metaaccount = {}
            except KeyError:
                finding_metaaccount = {}
            for key in list(finding_metaaccount):
                finding_metaaccount[key] = str(finding_metaaccount[key])
            # MetaTrails
            try:
                finding_metatrails = mh_findings[mh_finding]["metatrails"]
                if not finding_metatrails:
                    finding_metatrails = {}
            except KeyError:
                finding_metatrails = {}
            for key in list(finding_metatrails):
                finding_metatrails[key] = str(finding_metatrails[key])
            # Combining MetaChecks and MetaTags
            combined = {**finding_metatags, **finding_metachecks, **finding_metaaccount, **finding_metatrails}

            for finding in mh_findings[mh_finding]["findings"]:
                for f, v in finding.items():
                    FindingIdentifier = {"Id": v["Id"], "ProductArn": v["ProductArn"]}
                # To Do: Improve, only one update for resource.
                if combined:
                    self.logger.info(
                        "Enriching finding %s with MetaTags and MetaChecks: %s",
                        FindingIdentifier["Id"],
                        combined,
                    )
                    response = self.sh_client.batch_update_findings(
                        FindingIdentifiers=[FindingIdentifier],
                        UserDefinedFields=combined,
                        Note={"Text": "Enriching Findings", "UpdatedBy": "MetaHub"},
                    )
                    response_multiple.append(response)
                else:
                    self.logger.info(
                        "Ignoring finding %s as it has not MetaTags and MetaChecks",
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
