from lib.config.configuration import dangerous_iam_actions, trusted_accounts
from lib.impact.helpers import check_key, get_associated_resources, get_config_key


class Access:
    def __init__(self, logger):
        self.logger = logger

    def get_access(self, resource_arn, resource_values):
        self.logger.info("Calculating access for resource: %s", resource_arn)
        self.resource_arn = resource_arn
        self.resource_account_id = resource_values.get("AwsAccountId")

        access_checks = {
            "unrestricted": {},
            "wildcard_principal": {},
            "untrusted_principal": {},
            "cross_account_principal": {},
            "wildcard_actions": {},
            "dangerous_actions": {},
        }

        # Helper function to check policies and update access_checks
        def check_policy_and_update(policy_json, policy_name):
            if policy_json:
                policy_checks = self.check_policy(policy_json)
                for check_type, check_data in policy_checks.items():
                    if check_data:
                        access_checks[check_type].update({policy_name: check_data})

        # To Do:
        # - Check S3 Public Blocks
        # - Check S3 Bucket ACLs

        # To add as part of policy:
        # # Resource S3 Public Block
        # (
        #     s3_resource_block_public_acls,
        #     s3_resource_block_public_policy,
        #     s3_resource_ignore_public_acls,
        #     s3_resource_restrict_public_buckets,
        # ) = (
        #     False,
        #     False,
        #     False,
        #     False,
        # )
        # s3_resource_public_block = get_config_key(
        #     resource_values, "public_access_block_enabled"
        # )
        # if s3_resource_public_block:
        #     s3_resource_block_public_acls = s3_resource_public_block.get(
        #         "BlockPublicAcls"
        #     )
        #     s3_resource_block_public_policy = s3_resource_public_block.get(
        #         "BlockPublicPolicy"
        #     )
        #     s3_resource_ignore_public_acls = s3_resource_public_block.get(
        #         "IgnorePublicAcls"
        #     )
        #     s3_resource_restrict_public_buckets = s3_resource_public_block.get(
        #         "RestrictPublicBuckets"
        #     )
        # # Account S3 Public Block
        # (
        #     s3_account_block_public_acls,
        #     s3_account_block_public_policy,
        #     s3_account_ignore_public_acls,
        #     s3_account_restrict_public_buckets,
        # ) = (
        #     False,
        #     False,
        #     False,
        #     False,
        # )
        # s3_account_public_block = get_config_key(
        #     resource_values, "account_public_access_block_enabled"
        # )
        # if s3_account_public_block:
        #     s3_account_block_public_acls = s3_account_public_block.get(
        #         "BlockPublicAcls"
        #     )
        #     s3_account_block_public_policy = s3_account_public_block.get(
        #         "BlockPublicPolicy"
        #     )
        #     s3_account_ignore_public_acls = s3_account_public_block.get(
        #         "IgnorePublicAcls"
        #     )
        #     s3_account_restrict_public_buckets = s3_account_public_block.get(
        #         "RestrictPublicBuckets"
        #     )
        # # Let's create the final variables, based on the previous ones
        # (
        #     s3_block_public_acls,
        #     s3_block_public_policy,
        #     s3_ignore_public_acls,
        #     s3_restrict_public_buckets,
        # ) = (
        #     False,
        #     False,
        #     False,
        #     False,
        # )
        # if s3_resource_public_block or s3_account_public_block:
        #     if s3_resource_block_public_acls or s3_account_block_public_acls:
        #         pass
        #     if s3_resource_block_public_policy or s3_account_block_public_policy:
        #         pass
        #     if s3_resource_ignore_public_acls or s3_account_ignore_public_acls:
        #         pass
        #     if (
        #         s3_resource_restrict_public_buckets
        #         or s3_account_restrict_public_buckets
        #     ):
        #         pass

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

        return {"restricted": access_checks}

    def check_policy(self, policy):
        self.logger.info("Checking policy for resource: %s", self.resource_arn)
        failed_statements = {
            "wildcard_principal": [],
            "cross_account_principal": [],
            "untrusted_principal": [],
            "wildcard_actions": [],
            "unrestricted": [],
            "dangerous_actions": [],
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
            if self.wildcard_principal(statement):
                failed_statements["wildcard_principal"].append(statement)
            if self.cross_account_principal(statement):
                failed_statements["cross_account_principal"].append(statement)
            if self.untrusted_principal(statement):
                failed_statements["untrusted_principal"].append(statement)
            if self.wildcard_actions(statement):
                failed_statements["wildcard_actions"].append(statement)
            if self.unrestricted(statement):
                failed_statements["unrestricted"].append(statement)
            if self.dangerous_actions(statement):
                failed_statements["dangerous_actions"].append(statement)
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

    def santandarize_principals(self, principal):
        if "AWS" in principal:
            principals = principal["AWS"]
        elif "Service" in principal:
            principals = principal["Service"]
        elif "Federated" in principal:
            principals = principal["Federated"]
        else:
            principals = principal
        if type(principals) is not list:
            principals = [principals]
        return principals

    def standardize_actions(self, action):
        actions = action
        if type(action) is not list:
            actions = [action]
        return actions

    def standardize_statements(self, statement):
        statements = statement
        if type(statement) is not list:
            statements = [statement]
        return statements

    def wildcard_principal(self, statement):
        """
        Check if resource policy (S3, SQS) is allowed for principal wildcard
        """
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
            if principal == "*" or principal.get("AWS") == "*":
                return statement
        return False

    def cross_account_principal(self, statement):
        """
        Check if policy is allowed for principal cross account
        """
        amazon_accounts = ["cloudfront"]
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
            if principal and principal != "*" and principal.get("AWS") != "*":
                principals = self.santandarize_principals(principal)
                for p in principals:
                    # We are only scanninng ARN principals
                    if not p.startswith("arn:"):
                        continue
                    try:
                        account_id = p.split(":")[4]
                        if (
                            account_id != self.resource_account_id
                            and account_id not in amazon_accounts
                        ):
                            return statement
                    except (IndexError, TypeError) as err:
                        self.logger.warning(
                            "Parsing principal %s for resource %s doesn't look like ARN, ignoring.. - %s",
                            p,
                            self.resource_arn,
                            err,
                        )
        return False

    def untrusted_principal(self, statement):
        """ """
        if not trusted_accounts:
            self.logger.info(
                "No trusted accounts defined in configuration, skipping check for resource %s",
                self.resource_arn,
            )
            return False
        amazon_accounts = ["cloudfront"]
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
            if principal and principal != "*" and principal.get("AWS") != "*":
                principals = self.santandarize_principals(principal)
                for p in principals:
                    # We are only scanninng ARN principals
                    if not p.startswith("arn:"):
                        continue
                    try:
                        account_id = p.split(":")[4]
                        if (
                            account_id not in trusted_accounts
                            and account_id not in amazon_accounts
                            and account_id != self.resource_account_id
                        ):
                            return statement
                    except IndexError:
                        self.logger.warning(
                            "Parsing principal %s for resource %s doesn't look like ARN, ignoring.. ",
                            p,
                            self.resource_arn,
                        )
        return False

    def wildcard_actions(self, statement):
        """ """
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
            if action:
                actions = self.standardize_actions(action)
                for a in actions:
                    if "*" in a:
                        return statement
            # Not Action (all other actions are allowed)
            if not_action:
                return statement
        return False

    def dangerous_actions(self, statement):
        """ """
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
            if action:
                actions = self.standardize_actions(action)
                for a in actions:
                    if a in dangerous_iam_actions:
                        return statement
        return False

    def unrestricted(self, statement):
        """
        There is no principal defined. This means that the resource is unrestricted if the policy is attached to a resource.
        """
        (
            effect,
            principal,
            not_principal,
            condition,
            action,
            not_action,
            resource,
        ) = self.parse_statement(statement)
        suffix = "/0"
        if effect == "Allow":
            if principal == "*" or principal.get("AWS") == "*":
                if condition is not None:
                    # IpAddress Condition with /0
                    if suffix in str(condition.get("IpAddress")):
                        return statement
                    # To Do: Add other public conditions
                else:
                    # No Condition
                    return statement
            # Not Principal (all other principals)
            if not_principal is not None:
                return statement
        return False
