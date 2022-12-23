"""Integration AWS Security Hub"""
from sys import exit

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from AwsHelpers import assume_role, get_boto3_session


class SecurityHub:
    """Interfaces with the AWS Security Hub"""

    def __init__(self, logger, sh_region, sh_account=False, sh_role=False):
        self.logger = logger
        if not sh_role or not sh_account:
            self.sh_client = boto3.client("securityhub", region_name=sh_region)
        elif sh_role and sh_account:
            sh_role_assumend = assume_role(logger, sh_account, sh_role)
            shsess = get_boto3_session(sh_role_assumend)
            self.sh_client = shsess.client(
                service_name="securityhub", region_name=sh_region
            )
        else:
            self.logger.error("Missing data for assuming a Session to SH")
            exit(1)

    def get_findings(self, sh_filters):
        """Get Security Findings from Security Hub with Filters applied"""
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
            except ClientError as err:
                self.logger.error(
                    "An error occurred when attempting to gather SecurityHub data - %s",
                    err,
                )
                # No point proceeding without the data
                exit(1)
            except BotoCoreError as err:
                self.logger.error(
                    "An error occurred when attempting to gather SecurityHub data - %s",
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

    def parse_finding(self, finding):
        """Returns resurce ARN and finding parsed for it"""
        try:
            compliance = finding["Compliance"]
        except KeyError:
            compliance = None
        findings = {
            finding["Title"]: {
                "SeverityLabel": finding["Severity"]["Label"],
                "Workflow": finding["Workflow"],
                "RecordState": finding["RecordState"],
                "Compliance": compliance,
                "Id": finding["Id"],
                "ProductArn": finding["ProductArn"],
            },
        }
        return finding["Resources"][0]["Id"], findings

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
            # Combining MetaChecks and MetaTags
            combined = {**finding_metatags, **finding_metachecks}

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
                        Note={"Text": "test", "UpdatedBy": "MetaHub"},
                    )
                    response_multiple.append(response)
                else:
                    self.logger.info(
                        "Ignoring finding %s as it has not MetaTags and MetaChecks",
                        FindingIdentifier["Id"],
                    )
        return response_multiple
