from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    ParamValidationError,
)

import lib.context.resources
from lib.AwsHelpers import assume_role, get_account_id, get_boto3_client
from lib.config.resources import MetaHubResourcesConfig


class Context:
    def __init__(self, logger, finding, mh_filters_config, mh_filters_tags, mh_role):
        self.logger = logger
        self.parse_finding(finding)
        self.get_session(mh_role)
        self.mh_filters_config = mh_filters_config
        self.mh_filters_tags = mh_filters_tags
        # Move to Config:
        self.drilled_down = True

    def parse_finding(self, finding):
        self.finding = finding
        self.resource_account_id = finding["AwsAccountId"]
        self.resource_type = finding["Resources"][0]["Type"]
        self.resource_arn = finding["Resources"][0]["Id"]
        try:
            self.resource_region = finding["Region"]
        except KeyError:
            self.resource_region = finding["Resources"][0]["Region"]
        self.current_account_id = get_account_id(self.logger)

    def get_session(self, mh_role):
        if mh_role:
            self.sess = assume_role(self.logger, self.resource_account_id, mh_role)
        else:
            self.sess = None

    def get_handler(self):
        try:
            hndl = getattr(lib.context.resources, self.resource_type).Metacheck(
                self.logger, self.finding, self.mh_filters_config, self.sess
            )
        except (AttributeError, Exception) as err:
            if "has no attribute '" + self.resource_type in str(err):
                self.logger.info(
                    "get_handler undefined resource type - %s (%s)",
                    self.resource_arn,
                    self.resource_type,
                )
            elif "should return None" in str(err):
                self.logger.info(
                    "get_handler resource not found - %s (%s)",
                    self.resource_arn,
                    self.resource_type,
                )
            else:
                self.logger.error(
                    "get_handler error: %s - %s (%s)",
                    err,
                    self.resource_arn,
                    self.resource_type,
                )
            hndl = None
        return hndl

    def get_context_config(self):
        self.logger.info(
            "Running Get Context Config for Resource: %s (%s)",
            self.resource_arn,
            self.resource_type,
        )

        # Default Returns
        # If there are no filters, we forced to return True as we expected a Match always
        resource_matched = False if self.mh_filters_config else True
        resource_config = False

        # If the resources lives in another account, we need the --mh-assume-role
        if self.resource_account_id != self.current_account_id and not self.sess:
            self.logger.warning(
                "get_context_config resource %s lives in AWS Account %s, but you are logged in to AWS Account %s and not --mh-assume-role was provided. Ignoring...",
                self.resource_arn,
                self.resource_account_id,
                self.current_account_id,
            )
            return resource_config, resource_matched

        # Get Handler
        hnld = self.get_handler()
        if not hnld:
            return resource_config, resource_matched

        # Execute Drilled
        if self.drilled_down:
            try:
                hnld.execute_drilled_metachecks()
            except (AttributeError, Exception) as err:
                if "should return None" in str(err):
                    self.logger.info(
                        "Drilled get_handler resource not found - %s (%s)",
                        self.resource_arn,
                        self.resource_type,
                    )
                else:
                    self.logger.error(
                        "execute_drilled_metachecks error: %s - %s (%s)",
                        err,
                        self.resource_arn,
                        self.resource_type,
                    )

        # Execute Config Context
        try:
            resource_config, resource_matched = hnld.output_checks()
            self.logger.debug(
                "Config Result for Resource: %s (%s): \nConfig: %s \nMatched: %s",
                self.resource_arn,
                self.resource_type,
                resource_config,
                resource_matched,
            )
        except (AttributeError, Exception) as err:
            self.logger.error(
                "output_checks error: %s - %s (%s)",
                self.resource_type,
                self.resource_arn,
                err,
            )

        return resource_config, resource_matched

    def get_context_tags(self):
        self.logger.info(
            "Running Get Context Tags for Resource: %s (%s)",
            self.resource_arn,
            self.resource_type,
        )

        # Default Returns
        # If there are no filters, we forced to return True as we expected a Match always
        resource_matched = False if self.mh_filters_tags else True
        resource_tags = {}

        # Non-Taggable Resources
        if self.resource_type in (
            "AwsAccount",
            "Other",
            "AwsIamAccessKey",
            "AwsLogsLogGroup",
        ):
            return resource_tags, resource_matched

        # Execute Tags
        tags = False
        client = get_boto3_client(
            self.logger, "resourcegroupstaggingapi", self.resource_region, self.sess
        )
        try:
            response = client.get_resources(
                ResourceARNList=[
                    self.resource_arn,
                ]
            )
            try:
                tags = response["ResourceTagMappingList"][0]["Tags"]
            except IndexError:
                self.logger.info(
                    "No Tags found for resource: %s (%s)",
                    self.resource_arn,
                    self.resource_type,
                )
        except (ClientError, ParamValidationError, Exception) as err:
            self.logger.warning(
                "Error Fetching Tags for resource %s (%s) - %s",
                self.resource_arn,
                self.resource_type,
                err,
            )

        if tags:
            for tag in tags:
                resource_tags.update({(tag["Key"]): tag["Value"]})

            if self.mh_filters_tags:
                # Lower Case for better matching:
                mh_tags_values_lower = dict(
                    (k.lower(), v.lower()) for k, v in resource_tags.items()
                )
                mh_filters_tags_lower = dict(
                    (k.lower(), v.lower()) for k, v in self.mh_filters_tags.items()
                )
                compare = {
                    k: mh_tags_values_lower[k]
                    for k in mh_tags_values_lower
                    if k in mh_filters_tags_lower
                    and mh_tags_values_lower[k] == mh_filters_tags_lower[k]
                }
                self.logger.info(
                    "Evaluating Tags filter. Expected: "
                    + str(self.mh_filters_tags)
                    + " Found: "
                    + str(bool(compare))
                )
                if bool(compare):
                    resource_matched = True

        return resource_tags, resource_matched

    def get_context_account(self):
        self.logger.info(
            "Running Get Context Account for Resource: %s (%s)",
            self.resource_arn,
            self.resource_type,
        )

        account_config = {
            "Alias": self.get_account_alias(),
            "AlternateContact": self.get_account_alternate_contact(),
            "Organizations": self.get_account_organizations(),
        }

        return account_config

    def get_account_organizations(self):
        self.logger.info(
            "get_account_organizations for account: %s (%s)",
            self.resource_account_id,
            self.resource_arn,
        )
        # Organizations
        organizations = False
        organizations_client = get_boto3_client(
            self.logger, "organizations", self.resource_region, self.sess
        )
        try:
            response = organizations_client.describe_account(
                AccountId=self.resource_account_id
            )
            organizations_name = response["Account"]["Name"]
            response = organizations_client.list_parents(
                ChildId=self.resource_account_id
            )
            ou_id = response["Parents"][0]["Id"]
            if ou_id and response["Parents"][0]["Type"] == "ORGANIZATIONAL_UNIT":
                response = organizations_client.describe_organizational_unit(
                    OrganizationalUnitId=ou_id
                )
                organizations_ou = response["OrganizationalUnit"]["Name"]
            elif ou_id:
                organizations_ou = "ROOT"
            organizations = {
                "Name": organizations_name,
                "OU": organizations_ou,
            }
        except ClientError as err:
            self.logger.error(
                "Failed to describe_account: %s, for resource: %s - %s",
                self.resource_account_id,
                self.resource_arn,
                err,
            )

        return organizations

    def get_account_alternate_contact(self, alternate_contact_type="SECURITY"):
        # https://docs.aws.amazon.com/accounts/latest/reference/using-orgs-trusted-access.html
        # https://aws.amazon.com/blogs/mt/programmatically-managing-alternate-contacts-on-member-accounts-with-aws-organizations/

        self.logger.info(
            "get_account_alternate_contact for account: %s (%s)",
            self.resource_account_id,
            self.resource_arn,
        )
        alternate_contact = ""

        account_client = get_boto3_client(
            self.logger, "account", "us-east-1", self.sess
        )
        try:
            alternate_contact = account_client.get_alternate_contact(
                AccountId=self.resource_account_id,
                AlternateContactType=alternate_contact_type,
            ).get("AlternateContact")
        except (NoCredentialsError, ClientError, EndpointConnectionError):
            try:
                alternate_contact = account_client.get_alternate_contact(
                    AlternateContactType=alternate_contact_type
                ).get("AlternateContact")
            except (NoCredentialsError, ClientError, EndpointConnectionError) as err:
                if err.response["Error"]["Code"] == "ResourceNotFoundException":
                    self.logger.info(
                        "No alternate contact found for account %s (%s) - %s",
                        self.resource_account_id,
                        self.resource_arn,
                        err,
                    )
                else:
                    self.logger.warning(
                        "Failed to get_alternate_contact for account %s (%s) - %s",
                        self.resource_account_id,
                        self.resource_arn,
                        err,
                    )
        return alternate_contact

    def get_account_alias(self):
        self.logger.info(
            "get_account_alias for account: %s (%s)",
            self.resource_account_id,
            self.resource_arn,
        )
        aliases = ""

        iam_client = get_boto3_client(self.logger, "iam", "us-east-1", self.sess)
        try:
            aliases = iam_client.list_account_aliases()["AccountAliases"][0]
        except (NoCredentialsError, ClientError, EndpointConnectionError) as err:
            self.logger.error(
                "Failed to list_account_aliases: %s, for resource: %s - %s",
                self.resource_account_id,
                self.resource_arn,
                err,
            )
        except IndexError as err:
            self.logger.info(
                "No account alias found for account %s (%s) - %s",
                self.resource_account_id,
                self.resource_arn,
                err,
            )
        return aliases

    def get_context_cloudtrail(self):
        self.logger.info(
            "Running Get Context CloudTrail for Resource: %s (%s)",
            self.resource_arn,
            self.resource_type,
        )

        client = get_boto3_client(
            self.logger, "cloudtrail", self.resource_region, self.sess
        )

        trails = {}
        try:
            paginator = client.get_paginator("lookup_events")

            try:
                parsing_char = MetaHubResourcesConfig[self.resource_type][
                    "ResourceName"
                ]["parsing_char"]
                parsing_pos = MetaHubResourcesConfig[self.resource_type][
                    "ResourceName"
                ]["parsing_pos"]
                if parsing_char is not None:
                    ResourceName = self.resource_arn.split(parsing_char)[parsing_pos]
                else:
                    ResourceName = self.resource_arn
                event_names = MetaHubResourcesConfig[self.resource_type][
                    "metatrails_events"
                ]
            except KeyError:
                # No Config Defined
                return False

            page_iterator = paginator.paginate(
                LookupAttributes=[
                    {"AttributeKey": "ResourceName", "AttributeValue": ResourceName}
                ]
            )

            if event_names:
                for page in page_iterator:
                    for event in page["Events"]:
                        for event_name in event_names:
                            if event["EventName"] == event_name:
                                trails[event["EventName"]] = {
                                    "Username": event["Username"],
                                    "EventTime": str(event["EventTime"]),
                                    "EventId": event["EventId"],
                                }

        except (ClientError, ParamValidationError, Exception) as err:
            self.logger.warning(
                "Error Fetching CloudTrail for resource %s (%s) - %s",
                self.resource_arn,
                self.resource_type,
                err,
            )

        return trails
