"""Integration AWS Security Hub"""
from sys import exit

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from AwsHelpers import assume_role, get_boto3_session


class SecurityHub:
    """Interfaces with the AWS Security Hub"""

    def __init__(self, logger, sh_account=False, sh_role=False):
        self.logger = logger
        if not sh_role or not sh_account:
            self.sh_client = boto3.client("securityhub")
        elif sh_role and sh_account:
            sh_role_assumend = assume_role(logger, sh_account, sh_role)
            shsess = get_boto3_session(sh_role_assumend)
            self.sh_client = shsess.client(service_name="securityhub")
        else:
            self.logger.error("Missing data for assuming a Session to SH")
            exit(1)

    def set_filters(self, sh_filters):
        """Return filters for AWS Security Hub get_findings Call"""
        filters = {}
        for key, value in sh_filters.items():
            if key != "self" and value is not None:
                filters.update({key: [{"Comparison": "EQUALS", "Value": value}]})
        return filters

    def get_findings(self, sh_filters):
        """Get Security Findings from Security Hub with Filters applied"""
        findings = []
        next_token = ""
        while True:
            try:
                response = self.sh_client.get_findings(
                    Filters=self.set_filters(sh_filters),
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
                "Type": finding["Resources"][0]["Type"],
            },
        }
        return finding["Resources"][0]["Id"], findings

    def update_findings(self, mh_findings, update):
        update["FindingIdentifiers"] = []
        for mh_finding in mh_findings:
            for finding in mh_findings[mh_finding]["findings"]:
                for f, v in finding.items():
                    FindingIdentifier = {"Id": v["Id"], "ProductArn": v["ProductArn"]}
                    update["FindingIdentifiers"].append(FindingIdentifier)
        response = self.sh_client.batch_update_findings(
            FindingIdentifiers=update["FindingIdentifiers"],
            Workflow=update["Workflow"],
            Note=update["Note"],
        )
        return response
