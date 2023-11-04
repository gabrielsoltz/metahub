from botocore.exceptions import ClientError

from lib.AwsHelpers import get_boto3_client
from lib.config.configuration import dangereous_iam_actions, trusted_accounts


class PolicyHelper:
    def __init__(self, logger, resource_arn, resource_account_id, policy):
        self.logger = logger
        self.resource = resource_arn
        self.account_id = resource_account_id
        self.policy = policy

    def check_policy(self):
        self.logger.info("Checking policy for resource: %s", self.resource)
        failed_statements = {
            "wildcard_principal": [],
            "cross_account_principal": [],
            "untrusted_principal": [],
            "wildcard_actions": [],
            "unrestricted": [],
            "dangereous_actions": [],
        }
        statements = self.standardize_statements(self.policy["Statement"])
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
            if self.dangereous_actions(statement):
                failed_statements["dangereous_actions"].append(statement)
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
                "Failed to parse statement for resource %s", self.resource
            )
            return None, None, None, None, None, None, None
        return effect, principal, not_principal, condition, action, not_action, resource

    def santandarize_principals(self, principal):
        if "AWS" in principal:
            principals = principal["AWS"]
        elif "Service" in principal:
            return False
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
                    try:
                        account_id = p.split(":")[4]
                        if (
                            account_id != self.account_id
                            and account_id not in amazon_accounts
                        ):
                            return statement
                    except (IndexError, TypeError) as err:
                        self.logger.warning(
                            "Parsing principal %s for resource %s doesn't look like ARN, ignoring.. - %s",
                            p,
                            self.resource,
                            err,
                        )
                        # To DO: check identifiers-unique-ids
                        # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
        return False

    def untrusted_principal(self, statement):
        """ """
        if not trusted_accounts:
            self.logger.info(
                "No trusted accounts defined in configuration, skipping check for resource %s",
                self.resource,
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
                    try:
                        account_id = p.split(":")[4]
                        if (
                            account_id not in trusted_accounts
                            and account_id not in amazon_accounts
                            and account_id != self.account_id
                        ):
                            return statement
                    except IndexError:
                        self.logger.warning(
                            "Parsing principal %s for resource %s doesn't look like ARN, ignoring.. ",
                            p,
                            self.resource,
                        )
                        # To DO: check identifiers-unique-ids
                        # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
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

    def dangereous_actions(self, statement):
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
                    if a in dangereous_iam_actions:
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


class IamHelper:
    def __init__(self, logger, finding, role, sess, instance_profile=False):
        self.logger = logger
        self.region = finding["Region"]
        self.account = finding["AwsAccountId"]
        self.partition = finding["Resources"][0]["Id"].split(":")[1]
        self.finding = finding
        self.sess = sess
        self.resource_arn = finding["Resources"][0]["Id"]
        self.resource_id = finding["Resources"][0]["Id"].split("/")[1]
        self.iam_client = get_boto3_client(self.logger, "iam", self.region, self.sess)

    def get_role_from_instance_profile(self, instance_profile):
        if "/" in instance_profile:
            instance_profile_name = instance_profile.split("/")[-1]
        else:
            instance_profile_name = instance_profile
        try:
            response = self.iam_client.get_instance_profile(
                InstanceProfileName=instance_profile_name
            )
        except ClientError as e:
            self.logger.error(
                "Error getting role from instance profile %s: %s", instance_profile, e
            )
            return False

        return response["InstanceProfile"]["Roles"][0]["Arn"]


class SGHelper:
    def __init__(self, logger, sg_rules):
        self.logger = logger
        self.sg_rules = sg_rules

    def check_security_group_rules(self):
        failed_rules = {
            "is_ingress_rules_unrestricted": [],
            "is_egress_rules_unrestricted": [],
        }
        for rule in self.sg_rules:
            if (
                self.is_ingress_rule_unrestricted(rule)
                and rule not in failed_rules["is_ingress_rules_unrestricted"]
            ):
                failed_rules["is_ingress_rules_unrestricted"].append(rule)
            if (
                self.is_egress_rule_unrestricted(rule)
                and rule not in failed_rules["is_egress_rules_unrestricted"]
            ):
                failed_rules["is_egress_rules_unrestricted"].append(rule)
        return failed_rules

    def is_ingress_rule_unrestricted(self, rule):
        """ """
        if "CidrIpv4" in rule:
            if "0.0.0.0/0" in rule["CidrIpv4"] and not rule["IsEgress"]:
                return True
        if "CidrIpv6" in rule:
            if "::/0" in rule["CidrIpv6"] and not rule["IsEgress"]:
                return True
        return False

    def is_egress_rule_unrestricted(self, rule):
        """ """
        if "CidrIpv4" in rule:
            if "0.0.0.0/0" in rule["CidrIpv4"] and rule["IsEgress"]:
                return True
        if "CidrIpv6" in rule:
            if "::/0" in rule["CidrIpv6"] and rule["IsEgress"]:
                return True
        return False
