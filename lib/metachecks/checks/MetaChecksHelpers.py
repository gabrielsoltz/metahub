from aws_arn import generate_arn
from botocore.exceptions import ClientError

from lib.config import configuration


class ResourcePolicyChecker:
    def __init__(self, logger, finding, policy):
        self.logger = logger
        self.resource = finding["Resources"][0]["Id"]
        self.account_id = finding["AwsAccountId"]
        self.policy = policy

    def check_policy(self):
        self.logger.info("Checking policy for resource: %s", self.resource)
        failed_statements = {
            "is_principal_wildcard": [],
            "is_principal_cross_account": [],
            "is_principal_external": [],
            "is_public": [],
            "is_actions_wildcard": [],
        }
        for statement in self.policy["Statement"]:
            (
                effect,
                principal,
                not_principal,
                condition,
                action,
                not_action,
            ) = self.parse_statement(statement)
            if effect == "Allow":
                if self.is_principal_wildcard(statement):
                    failed_statements["is_principal_wildcard"].append(statement)
                if self.is_principal_cross_account(statement):
                    failed_statements["is_principal_cross_account"].append(statement)
                if self.is_principal_external(statement):
                    failed_statements["is_principal_external"].append(statement)
                if self.is_public(statement):
                    failed_statements["is_public"].append(statement)
                if self.is_actions_wildcard(statement):
                    failed_statements["is_actions_wildcard"].append(statement)
        return failed_statements

    def parse_statement(self, statement):
        effect = statement.get("Effect", None)
        principal = statement.get("Principal", {})
        not_principal = statement.get("NotPrincipal", None)
        condition = statement.get("Condition", None)
        action = statement.get("Action", None)
        not_action = statement.get("NotAction", None)
        return effect, principal, not_principal, condition, action, not_action

    def is_principal_wildcard(self, statement):
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
        ) = self.parse_statement(statement)
        if principal == "*" or principal.get("AWS") == "*":
            return statement
        return False

    def is_principal_cross_account(self, statement):
        """
        Check if policy is allowed for principal cross account
        """
        (
            effect,
            principal,
            not_principal,
            condition,
            action,
            not_action,
        ) = self.parse_statement(statement)
        if principal and principal != "*" and principal.get("AWS") != "*":
            if "AWS" in principal:
                principals = principal["AWS"]
            elif "Service" in principal:
                return False
            else:
                principals = principal
            if type(principals) is not list:
                principals = [principals]
            for p in principals:
                try:
                    account_id = p.split(":")[4]
                    if account_id != self.account_id:
                        if account_id not in ("cloudfront"):
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

    def is_principal_external(self, statement):
        """ """
        internal_accounts = configuration.trusted_accounts
        amazon_accounts = "cloudfront"
        (
            effect,
            principal,
            not_principal,
            condition,
            action,
            not_action,
        ) = self.parse_statement(statement)
        if principal and principal != "*" and principal.get("AWS") != "*":
            if "AWS" in principal:
                principals = principal["AWS"]
            elif "Service" in principal:
                return False
            else:
                principals = principal
            if type(principals) is not list:
                principals = [principals]
            for p in principals:
                try:
                    account_id = p.split(":")[4]
                    if (
                        account_id not in internal_accounts
                        and account_id not in amazon_accounts
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

    def is_public(self, statement):
        """ """
        (
            effect,
            principal,
            not_principal,
            condition,
            action,
            not_action,
        ) = self.parse_statement(statement)
        suffix = "/0"
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

    def is_actions_wildcard(self, statement):
        """ """
        (
            effect,
            principal,
            not_principal,
            condition,
            action,
            not_action,
        ) = self.parse_statement(statement)
        if action:
            if "*" in action:
                return statement
        # Not Action (all other actions)
        if not_action:
            return statement
        return False


import boto3


class SecurityGroupChecker:
    def __init__(self, logger, finding, sg, sess):
        # SG is a list or dictionary of ARNs or IDs
        self.logger = logger
        self.resource = finding["Resources"][0]["Id"]
        self.account_id = finding["AwsAccountId"]
        self.sg = sg
        region = finding["Region"]
        if not sess:
            self.ec2_client = boto3.client("ec2", region_name=region)
        else:
            self.ec2_client = sess.client(service_name="ec2", region_name=region)
        self.security_group_rules = self._describe_security_group_rules()

    def _describe_security_group_rules(self):
        response = self.ec2_client.describe_security_group_rules(
            Filters=[
                {"Name": "group-id", "Values": [sg.split("/")[1] for sg in self.sg]},
            ],
        )
        if response["SecurityGroupRules"]:
            return response["SecurityGroupRules"]
        return False

    def check_security_group(self):
        self.logger.info("Checking SG %s for resource: %s", self.sg, self.resource)
        failed_rules = {
            "is_ingress_rules_unrestricted": [],
            "is_egress_rule_unrestricted": [],
        }
        if self.security_group_rules:
            for rule in self.security_group_rules:
                if (
                    self.is_ingress_rules_unrestricted(rule)
                    and rule not in failed_rules["is_ingress_rules_unrestricted"]
                ):
                    failed_rules["is_ingress_rules_unrestricted"].append(rule)
                if (
                    self.is_egress_rule_unrestricted(rule)
                    and rule not in failed_rules["is_egress_rule_unrestricted"]
                ):
                    failed_rules["is_egress_rule_unrestricted"].append(rule)
        return failed_rules

    def is_ingress_rules_unrestricted(self, rule):
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


class ResourceIamRoleChecker:
    def __init__(self, logger, finding, role, sess):
        self.logger = logger
        self.resource = finding["Resources"][0]["Id"]
        self.account_id = finding["AwsAccountId"]
        self.role = role
        self.region = finding["Region"]
        self.partition = "aws"
        self.sess = sess
        self.finding = finding
        if not sess:
            self.iam_client = boto3.client("iam", region_name=self.region)
        else:
            self.iam_client = sess.client(service_name="iam", region_name=self.region)
        self.role_policies = self.describe_role_policies()

    def describe_role_policies(self):
        policies = []

        list_role_policies = self.iam_client.list_role_policies(
            RoleName=self.role.split("/")[-1]
        )
        if list_role_policies["PolicyNames"]:
            for policy_name in list_role_policies["PolicyNames"]:
                arn = generate_arn(
                    policy_name,
                    "iam",
                    "policy",
                    self.region,
                    self.account_id,
                    self.partition,
                )
                policies.append(arn)

        list_attached_role_policies = self.iam_client.list_attached_role_policies(
            RoleName=self.role.split("/")[-1]
        )
        if list_attached_role_policies["AttachedPolicies"]:
            for attached_policy in list_attached_role_policies["AttachedPolicies"]:
                policies.append(attached_policy["PolicyArn"])

        return policies

    def get_policy(self, policy_arn):
        try:
            policy_version_id = self.iam_client.get_policy(PolicyArn=policy_arn)[
                "Policy"
            ]["DefaultVersionId"]
            response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=policy_version_id
            )
            return response["PolicyVersion"]["Document"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                response = self.iam_client.get_role_policy(
                    RoleName=self.role.split("/")[-1],
                    PolicyName=policy_arn.split("/")[-1],
                )
                return response["PolicyDocument"]

    def check_role_policies(self):
        self.logger.info("Checking role %s for resource: %s", self.role, self.resource)
        roles_checks = {
            "iam_policies": {},
        }
        for policy in self.role_policies:
            policy_doc = self.get_policy(policy)
            check_policy = ResourcePolicyChecker(
                self.logger, self.finding, policy_doc
            ).check_policy()
            roles_checks["iam_policies"][policy] = {
                "policy_checks": check_policy,
                "policy": policy_doc,
            }
        return roles_checks


class VPCChecker:
    def __init__(self, logger, finding, role, sess):
        self.logger = logger
        self.resource = finding["Resources"][0]["Id"]
        self.account_id = finding["AwsAccountId"]
        self.role = role
        self.region = finding["Region"]
        self.partition = "aws"
        self.sess = sess
        self.finding = finding
        if not sess:
            self.iam_client = boto3.client("iam", region_name=self.region)
        else:
            self.iam_client = sess.client(service_name="iam", region_name=self.region)
