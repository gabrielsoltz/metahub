from lib.context.resources.ContextHelpers import PolicyHelper
from lib.impact.helpers import check_key, get_associated_resources, get_config_key


class Access:
    def __init__(self, logger):
        self.logger = logger

    def get_access(self, resource_arn, resource_values):
        self.logger.info("Calculating access for resource: %s", resource_arn)

        resource_account_id = resource_values.get("AwsAccountId")
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
            policy_checks = PolicyHelper(
                self.logger, resource_arn, resource_account_id, policy_json
            ).check_policy()
            for check_type, check_data in policy_checks.items():
                if check_data:
                    access_checks[check_type].update({policy_name: check_data})

        # Resource Policy
        resource_policy = get_config_key(resource_values, "resource_policy")
        if resource_policy is not None:
            check_policy_and_update(resource_policy, "resource_policy")

        # Inline IAM Policies
        inline_policies = get_config_key(resource_values, "iam_inline_policies")
        if inline_policies is not None:
            for policy_arn, policy_config in inline_policies.items():
                check_policy_and_update(policy_config, policy_arn)

        # Associated IAM Policies
        iam_policies = get_associated_resources(resource_values, "iam_policies")
        if iam_policies is not None:
            for policy_arn, policy_config in iam_policies.items():
                iam_policy_resource_policy = get_config_key(
                    policy_config, "resource_policy"
                )
                if iam_policy_resource_policy is not None:
                    check_policy_and_update(
                        policy_config["config"]["resource_policy"], policy_arn
                    )

        # Associated IAM Roles (we check again inline and associated)
        iam_roles = get_associated_resources(resource_values, "iam_roles")
        if iam_roles is not None:
            for role_arn, role_config in iam_roles.items():
                # Inline IAM Policies
                iam_role_inline_policies = get_config_key(
                    resource_values, "iam_inline_policies"
                )
                if iam_role_inline_policies is not None:
                    for policy_arn, policy_config in iam_role_inline_policies.items():
                        check_policy_and_update(policy_config, policy_arn)
                # Associated IAM Policies
                iam_role_iam_policies = get_associated_resources(
                    role_config, "iam_policies"
                )
                if iam_role_iam_policies is not None:
                    for policy_arn, policy_config in iam_role_iam_policies.items():
                        iam_policy_resource_policy = get_config_key(
                            policy_config, "resource_policy"
                        )
                        if iam_policy_resource_policy is not None:
                            check_policy_and_update(
                                policy_config["config"]["resource_policy"], policy_arn
                            )

        # Remove empty checks
        for check_type, check_data in list(access_checks.items()):
            if not check_data:
                del access_checks[check_type]

        # If no config and no associations, return unknown
        if not check_key(resource_values, "config") and not check_key(
            resource_values, "associations"
        ):
            return {"unknown": {}}

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
