from lib.config.configuration import dangerous_iam_actions, trusted_accounts
from lib.impact.helpers import check_key, get_associated_resources, get_config_key


class Access:
    def __init__(self, logger):
        self.logger = logger

    def get_access(self, resource_arn, resource_values):
        self.logger.info("Calculating access for resource: %s", resource_arn)
        self.resource_arn = resource_arn
        self.resource_account_id = resource_values.get("AwsAccountId")
        self.cannonical_user_id = get_config_key(resource_values, "cannonical_user_id")

        access_checks = {
            "unrestricted": {},
            "wildcard_principal": {},
            "untrusted_principal": {},
            "cross_account_principal": {},
            "wildcard_actions": {},
            "dangerous_actions": {},
            "unrestricted_services": {},
        }

        # Helper function to check policies and update access_checks
        def check_policy_and_update(policy_json, policy_name):
            if policy_json:
                policy_checks = self.check_policy(policy_json)
                for check_type, check_data in policy_checks.items():
                    if check_data:
                        access_checks[check_type].update({policy_name: check_data})

        # Helper function to check policies and update access_checks
        def check_bucket_acl_and_update(policy_json, policy_name):
            if policy_json:
                policy_checks = self.check_bucket_acl(policy_json)
                for check_type, check_data in policy_checks.items():
                    if check_data:
                        access_checks[check_type].update({policy_name: check_data})

        # Check S3 Public Blocks
        (
            self.s3_block_public_acls,
            self.s3_block_public_policy,
            self.s3_ignore_public_acls,
            self.s3_restrict_public_buckets,
        ) = self.check_s3_public_block(resource_values)

        # Bucket ACL
        bucket_acl = get_config_key(resource_values, "bucket_acl")
        if bucket_acl:
            check_bucket_acl_and_update(bucket_acl, "bucket_acl")

        # Resource Policy
        resource_policy = get_config_key(resource_values, "resource_policy")
        if resource_policy:
            check_policy_and_update(resource_policy, "resource_policy")

        # Inline IAM Policies
        inline_policies = get_config_key(resource_values, "iam_inline_policies")
        if inline_policies:
            for policy_arn, policy_config in inline_policies.items():
                if policy_config:
                    check_policy_and_update(policy_config, policy_arn)

        # Associated IAM Policies
        iam_policies = get_associated_resources(resource_values, "iam_policies")
        if iam_policies:
            for policy_arn, policy_config in iam_policies.items():
                if policy_config:
                    iam_policy_resource_policy = get_config_key(
                        policy_config, "resource_policy"
                    )
                    if iam_policy_resource_policy:
                        check_policy_and_update(
                            policy_config["config"]["resource_policy"], policy_arn
                        )

        # Associated IAM Roles (we check again inline and associated)
        iam_roles = get_associated_resources(resource_values, "iam_roles")
        if iam_roles:
            for role_arn, role_config in iam_roles.items():
                if role_config:
                    # Inline IAM Policies
                    iam_role_inline_policies = get_config_key(
                        resource_values, "iam_inline_policies"
                    )
                    if iam_role_inline_policies:
                        for (
                            policy_arn,
                            policy_config,
                        ) in iam_role_inline_policies.items():
                            check_policy_and_update(policy_config, policy_arn)
                    # Associated IAM Policies
                    iam_role_iam_policies = get_associated_resources(
                        role_config, "iam_policies"
                    )
                    if iam_role_iam_policies:
                        for policy_arn, policy_config in iam_role_iam_policies.items():
                            if policy_config:
                                iam_policy_resource_policy = get_config_key(
                                    policy_config, "resource_policy"
                                )
                                if iam_policy_resource_policy:
                                    check_policy_and_update(
                                        policy_config["config"]["resource_policy"],
                                        policy_arn,
                                    )

        # Remove empty checks
        for check_type, check_data in list(access_checks.items()):
            if not check_data:
                del access_checks[check_type]

        # If no config and no associations, return unknown
        if not check_key(resource_values, "config") and not check_key(
            resource_values, "associations"
        ):
            return {"unknown": access_checks}

        # Resources without policies are unknown.
        if (
            bucket_acl is None
            and resource_policy is None
            and inline_policies is None
            and iam_policies is None
            and iam_roles is None
        ):
            return {"unknown": access_checks}

        # We return the most critical access check
        if "unrestricted" in access_checks:
            return {"unrestricted": access_checks}
        if "untrusted_principal" in access_checks:
            return {"untrusted-principal": access_checks}
        if "dangerous_actions" in access_checks:
            return {"dangerous-actions": access_checks}
        if "wildcard_actions" in access_checks:
            return {"unrestricted-actions": access_checks}
        if "cross_account_principal" in access_checks:
            return {"cross-account-principal": access_checks}
        if "wildcard_principal" in access_checks:
            return {"unrestricted-principal": access_checks}
        if "unrestricted_services" in access_checks:
            return {"unrestricted-services": access_checks}

        return {"restricted": access_checks}

    def check_policy(self, policy):
        principal_amazon_accounts = ["cloudfront"]

        self.logger.info("Checking policy for resource: %s", self.resource_arn)
        failed_statements = {
            "wildcard_principal": [],
            "cross_account_principal": [],
            "untrusted_principal": [],
            "wildcard_actions": [],
            "unrestricted": [],
            "dangerous_actions": [],
            "unrestricted_services": [],
        }
        statements = []
        try:
            statements = self.standardize_statements(policy["Statement"])
        except TypeError:
            self.logger.error(
                "Failed to parse policy for resource %s", self.resource_arn, policy
            )
            return failed_statements
        for statement in statements:
            (
                effect,
                principal,
                not_principal,
                condition,
                action,
                not_action,
                resource,
            ) = self.parse_statement(statement)
            if effect == "Allow":
                # Wildcard or Unrestricted Principal
                all_principals = self.standardize_principals(principal)
                for p in all_principals:
                    if "*" in p:
                        if condition and not self.is_unrestricted_conditions(condition):
                            if statement not in failed_statements["wildcard_principal"]:
                                failed_statements["wildcard_principal"].append(
                                    statement
                                )
                        else:
                            if self.s3_restrict_public_buckets:
                                if (
                                    statement
                                    not in failed_statements["wildcard_principal"]
                                ):
                                    failed_statements["wildcard_principal"].append(
                                        statement
                                    )
                            else:
                                if statement not in failed_statements["unrestricted"]:
                                    failed_statements["unrestricted"].append(statement)
                if (
                    not_principal is not None
                ):  # If Allow and Not Principal, means all other principals
                    if condition and not self.is_unrestricted_conditions(condition):
                        if statement not in failed_statements["wildcard_principal"]:
                            failed_statements["wildcard_principal"].append(statement)
                    else:
                        if self.s3_restrict_public_buckets:
                            if statement not in failed_statements["wildcard_principal"]:
                                failed_statements["wildcard_principal"].append(
                                    statement
                                )
                        else:
                            if statement not in failed_statements["unrestricted"]:
                                failed_statements["unrestricted"].append(statement)
                # Cross Account or Untrusted Principal
                aws_principals = self.standardize_principals(principal, "AWS")
                for p in aws_principals:
                    if "*" not in p:
                        if p.startswith("arn:"):
                            account_id = p.split(":")[4]
                        else:
                            account_id = p
                        if (
                            account_id != self.resource_account_id
                            and account_id not in principal_amazon_accounts
                        ):
                            if trusted_accounts and account_id not in trusted_accounts:
                                if (
                                    statement
                                    not in failed_statements["untrusted_principal"]
                                ):
                                    failed_statements["untrusted_principal"].append(
                                        statement
                                    )
                            else:
                                if (
                                    statement
                                    not in failed_statements["cross_account_principal"]
                                ):
                                    failed_statements["cross_account_principal"].append(
                                        statement
                                    )
                # Unrestricted Service
                service_principals = self.standardize_principals(principal, "Service")
                for p in service_principals:
                    if not condition or (
                        condition and self.is_unrestricted_conditions(condition)
                    ):
                        if statement not in failed_statements["unrestricted_services"]:
                            failed_statements["unrestricted_services"].append(statement)
                # Wildcard or Dangerous Actions
                actions = self.standardize_actions(action)
                for a in actions:
                    if a in dangerous_iam_actions:
                        if statement not in failed_statements["dangerous_actions"]:
                            failed_statements["dangerous_actions"].append(statement)
                    if "*" in a:
                        if statement not in failed_statements["wildcard_actions"]:
                            failed_statements["wildcard_actions"].append(statement)

        return failed_statements

    def check_bucket_acl(self, bucket_acl):
        self.logger.info("Checking bucket acl for resource: %s", self.resource_arn)
        failed_statements = {
            "cross_account_principal": [],
            "unrestricted": [],
        }
        if bucket_acl:
            for grant in bucket_acl:
                if grant["Grantee"]["Type"] == "CanonicalUser":
                    if self.cannonical_user_id:
                        if grant["Grantee"]["ID"] != self.cannonical_user_id:
                            # perm = grant["Permission"]
                            failed_statements["cross_account_principal"].append(grant)
                if grant["Grantee"]["Type"] == "Group":
                    # use only last part of URL as a key:
                    #   http://acs.amazonaws.com/groups/global/AuthenticatedUsers
                    #   http://acs.amazonaws.com/groups/global/AllUsers
                    who = grant["Grantee"]["URI"].split("/")[-1]
                    if who == "AllUsers" or who == "AuthenticatedUsers":
                        if self.s3_ignore_public_acls:
                            failed_statements["wildcard_principal"].append(grant)
                        else:
                            failed_statements["unrestricted"].append(grant)

        return failed_statements

    def parse_statement(self, statement):
        try:
            effect = statement.get("Effect", None)
            principal = statement.get("Principal", {})
            not_principal = statement.get("NotPrincipal", None)
            condition = statement.get("Condition", None)
            action = statement.get("Action", None)
            not_action = statement.get("NotAction", None)
            resource = statement.get("Resource", None)
        except AttributeError:
            self.logger.error(
                "Failed to parse statement for resource %s", self.resource_arn
            )
            return None, None, None, None, None, None, None
        return effect, principal, not_principal, condition, action, not_action, resource

    def standardize_principals(self, principal, prequiredtype=None):
        principals = []
        if principal == "*":
            principals.append("*")
        else:
            if not prequiredtype:
                for ptype in principal:
                    if type(principal[ptype]) is list:
                        principals.extend(principal[ptype])
                    else:
                        principals.append(principal[ptype])
            if prequiredtype and prequiredtype in principal:
                if type(principal[prequiredtype]) is list:
                    principals.extend(principal[prequiredtype])
                else:
                    principals.append(principal[prequiredtype])
        return principals

    def standardize_actions(self, action):
        actions = []
        if action:
            actions = action
            if type(action) is not list:
                actions = [action]
        return actions

    def standardize_statements(self, statement):
        statements = statement
        if type(statement) is not list:
            statements = [statement]
        return statements

    def is_unrestricted_conditions(self, condition):
        if condition:
            if "IpAddress" in condition:
                if "*" in condition["IpAddress"]:
                    return True
                if "/0" in condition["IpAddress"]:
                    return True
        return False

    def check_s3_public_block(self, resource_values):
        # Resource S3 Public Block
        (
            s3_resource_block_public_acls,
            s3_resource_block_public_policy,
            s3_resource_ignore_public_acls,
            s3_resource_restrict_public_buckets,
        ) = (
            False,
            False,
            False,
            False,
        )
        s3_resource_public_block = get_config_key(
            resource_values, "public_access_block_enabled"
        )
        if s3_resource_public_block:
            s3_resource_block_public_acls = s3_resource_public_block.get(
                "BlockPublicAcls"
            )
            s3_resource_block_public_policy = s3_resource_public_block.get(
                "BlockPublicPolicy"
            )
            s3_resource_ignore_public_acls = s3_resource_public_block.get(
                "IgnorePublicAcls"
            )
            s3_resource_restrict_public_buckets = s3_resource_public_block.get(
                "RestrictPublicBuckets"
            )
        # Account S3 Public Block
        (
            s3_account_block_public_acls,
            s3_account_block_public_policy,
            s3_account_ignore_public_acls,
            s3_account_restrict_public_buckets,
        ) = (
            False,
            False,
            False,
            False,
        )
        s3_account_public_block = get_config_key(
            resource_values, "account_public_access_block_enabled"
        )
        if s3_account_public_block:
            s3_account_block_public_acls = s3_account_public_block.get(
                "BlockPublicAcls"
            )
            s3_account_block_public_policy = s3_account_public_block.get(
                "BlockPublicPolicy"
            )
            s3_account_ignore_public_acls = s3_account_public_block.get(
                "IgnorePublicAcls"
            )
            s3_account_restrict_public_buckets = s3_account_public_block.get(
                "RestrictPublicBuckets"
            )
        # Let's create the final variables, based on the previous ones
        (
            s3_block_public_acls,
            s3_block_public_policy,
            s3_ignore_public_acls,
            s3_restrict_public_buckets,
        ) = (
            False,
            False,
            False,
            False,
        )
        if s3_resource_block_public_acls or s3_account_block_public_acls:
            s3_block_public_acls = True
        if s3_resource_block_public_policy or s3_account_block_public_policy:
            s3_block_public_policy = True
        if s3_resource_ignore_public_acls or s3_account_ignore_public_acls:
            s3_ignore_public_acls = True
        if s3_resource_restrict_public_buckets or s3_account_restrict_public_buckets:
            s3_restrict_public_buckets = True
        return (
            s3_block_public_acls,
            s3_block_public_policy,
            s3_ignore_public_acls,
            s3_restrict_public_buckets,
        )
