from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    ParamValidationError,
)

import lib.context.resources
from lib.AwsHelpers import assume_role, get_boto3_client
from lib.config.resources import MetaHubResourcesConfig
from lib.securityhub import parse_region


class Context:
    def __init__(
        self,
        logger,
        finding,
        mh_filters_config,
        mh_filters_tags,
        mh_role,
        cached_associated_resources,
        current_account_id,
    ):
        self.logger = logger
        self.parse_finding(finding)
        self.get_session(mh_role)
        self.mh_filters_config = mh_filters_config
        self.mh_filters_tags = mh_filters_tags
        self.cached_associated_resources = cached_associated_resources
        self.drilled_down = True
        self.current_account_id = current_account_id

    def convert_tags_to_key_value(self, tags):
        """When reading the Tags from the finding, the format is a list of dictionaries, we need to convert it to a dictionary of key-value pairs"""
        return [{"Key": key, "Value": value} for key, value in tags.items()]

    def parse_finding(self, finding):
        self.finding = finding
        self.resource_account_id = finding["AwsAccountId"]
        self.resources = finding.get("Resources")
        if self.resources:
            self.resource_type = self.resources[0]["Type"]
            self.resource_arn = self.resources[0]["Id"]
            self.resource_tags = self.resources[0].get("Tags", False)
        else:
            self.resource_type = "Unknown"
            self.resource_arn = "Unknown"
            self.resource_tags = False
        self.resource_region = parse_region(self.resource_arn, self.finding)

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
        all_associations = {}

        # If the resources lives in another account, we need the --mh-assume-role
        if self.resource_account_id != self.current_account_id and not self.sess:
            self.logger.warning(
                "get_context_config resource %s lives in AWS Account %s, but you are logged in to AWS Account %s and not --mh-assume-role was provided. Ignoring...",
                self.resource_arn,
                self.resource_account_id,
                self.current_account_id,
            )
            return resource_config, resource_matched, all_associations

        # Get Handler
        hnld = self.get_handler()
        if not hnld:
            return resource_config, resource_matched, all_associations

        # Execute Drilled
        if self.drilled_down:
            try:
                all_associations = hnld.execute_drilled_metachecks(
                    self.cached_associated_resources
                )
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

        return resource_config, resource_matched, all_associations

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

        # Check if Tags are already available in the resource object
        if not self.resource_tags:
            tags = False
            client = get_boto3_client(
                self.logger, "resourcegroupstaggingapi", self.resource_region, self.sess
            )

            # Some tools sometimes return incorrect ARNs for some resources, here is an attemp to fix them
            def fix_arn(arn, resource_type):
                # Route53 Hosted Zone with Account Id
                if resource_type == "AwsRoute53HostedZone":
                    if arn.split(":")[4] != "":
                        fixed_arn = arn.replace(arn.split(":")[4], "")
                        return fixed_arn
                return arn

            try:
                response = client.get_resources(
                    ResourceARNList=[fix_arn(self.resource_arn, self.resource_type)]
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
        else:
            tags = self.convert_tags_to_key_value(self.resource_tags)

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
        organizations_client = get_boto3_client(
            self.logger, "organizations", self.resource_region, self.sess
        )
        # Describe Organization
        try:
            response_describe_organization = (
                organizations_client.describe_organization().get("Organization")
            )
            organization_arn = response_describe_organization.get("Arn")
            organization_id = response_describe_organization.get("Id")
            organization_master_id = response_describe_organization.get(
                "MasterAccountId"
            )
            organization_master_email = response_describe_organization.get(
                "MasterAccountEmail"
            )
            organization_feature_set = response_describe_organization.get("FeatureSet")
            # Describe Delegations
            # This only works if we are the master account or a delegated administrator, but we try anyways to get the info
            organization_delegated_administrators = {}
            try:
                response_list_delegated_administrators = (
                    organizations_client.list_delegated_administrators().get(
                        "DelegatedAdministrators"
                    )
                )
                if response_list_delegated_administrators:
                    for (
                        delegated_administrator
                    ) in response_list_delegated_administrators:
                        organization_delegated_administrators[
                            delegated_administrator.get("Id")
                        ] = {}
            except ClientError as err:
                if not err.response["Error"]["Code"] == "AccessDeniedException":
                    self.logger.warning(
                        "Failed to list_delegated_administrators: %s, for resource: %s - %s",
                        self.resource_account_id,
                        self.resource_arn,
                        err,
                    )
            # Organizations Details
            organizations = {
                "Arn": organization_arn,
                "Id": organization_id,
                "MasterAccountId": organization_master_id,
                "MasterAccountEmail": organization_master_email,
                "FeatureSet": organization_feature_set,
                "DelegatedAdministrators": organization_delegated_administrators,
            }
        except ClientError as err:
            organizations = False
            if not err.response["Error"]["Code"] == "AWSOrganizationsNotInUseException":
                self.logger.error(
                    "Failed to describe_organization: %s, for resource: %s - %s",
                    self.resource_account_id,
                    self.resource_arn,
                    err,
                )
        except Exception as err:
            organizations = False
            self.logger.error(
                "Failed to describe_organization: %s, for resource: %s - %s",
                self.resource_account_id,
                self.resource_arn,
                err,
            )
        return organizations

    def get_account_organizations_details(self):
        # The following operations can be called only from the organization’s management account or by a member account that is a delegated administrator.
        organizations_details = {}
        self.logger.info(
            "get_account_organizations_details for account: %s (%s)",
            self.resource_account_id,
            self.resource_arn,
        )
        # Organizations
        organizations_client = get_boto3_client(
            self.logger, "organizations", self.resource_region, self.sess
        )
        # Get parent ID and OU
        try:
            response_list_parents = organizations_client.list_parents(
                ChildId=self.resource_account_id
            )
            parent_id = response_list_parents["Parents"][0]["Id"]
            parent_type = response_list_parents["Parents"][0]["Type"]
            if parent_id and parent_type == "ORGANIZATIONAL_UNIT":
                response_describe_organizational_unit = (
                    organizations_client.describe_organizational_unit(
                        OrganizationalUnitId=parent_id
                    )
                )
                organizations_ou = response_describe_organizational_unit[
                    "OrganizationalUnit"
                ]["Name"]
            elif parent_id:
                organizations_ou = "ROOT"
            organizations_details["ParentId"] = parent_id
            organizations_details["ParentType"] = parent_type
            organizations_details["OU"] = organizations_ou
        except ClientError as err:
            if not err.response["Error"]["Code"] == "AccessDeniedException":
                self.logger.warning(
                    "Failed to list_parents: %s, for resource: %s - %s",
                    self.resource_account_id,
                    self.resource_arn,
                    err,
                )
        # Policies
        available_organizations_policies = [
            "SERVICE_CONTROL_POLICY",
            "TAG_POLICY",
            "BACKUP_POLICY",
            "AISERVICES_OPT_OUT_POLICY",
        ]
        organizations_details["Policies"] = {}
        for policy_type in available_organizations_policies:
            response_list_policies = organizations_client.list_policies(
                Filter=policy_type
            )
            if response_list_policies.get("Policies"):
                for policy in response_list_policies.get("Policies"):
                    policy_id = policy.get("Id")
                    policy_name = policy.get("Name")
                    policy_arn = policy.get("Arn")
                    policy_type = policy.get("Type")
                    policy_description = policy.get("Description")
                    policy_awsmanaged = policy.get("AwsManaged")
                    targes = organizations_client.list_targets_for_policy(
                        PolicyId=policy_id
                    )["Targets"]
                    organizations_details["Policies"][policy_id] = {
                        "Name": policy_name,
                        "Arn": policy_arn,
                        "Type": policy_type,
                        "Description": policy_description,
                        "AwsManaged": policy_awsmanaged,
                        "Targets": targes,
                    }

        return organizations_details

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
            except (ClientError, EndpointConnectionError) as err:
                if err.response["Error"]["Code"] == "ResourceNotFoundException":
                    self.logger.info(
                        "No alternate contact found for account %s (%s) - %s",
                        self.resource_account_id,
                        self.resource_arn,
                        err,
                    )
            except Exception as err:
                self.logger.error(
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
