class MetaChecksBase:
    def __init__(
        self,
        logger,
        finding,
        mh_filters_checks,
        sess,
        drilled=False,
    ):
        self.logger = logger

    def output_checks(self):
        """
        return mh_values_checks: MetaChecks values dictionary.
        return mh_matched_checks: True if mh-filters-checks matchs one of metachecks the values
        """

        # mode = "atleast1"
        mode = "all"

        mh_values_checks = {}
        # If there is no filters, we force match to True
        mh_matched_checks = False if self.mh_filters_checks else True
        # All Checks needs to be matched
        mh_matched_checks_all_checks = True

        # Config
        context_config = self.checks()
        for check, value in context_config.items():
            if check in self.mh_filters_checks:
                self.logger.info(
                    "Evaluating MetaCheck filter ("
                    + check
                    + "). Expected: "
                    + str(self.mh_filters_checks[check])
                    + " Found: "
                    + str(bool(value))
                )
                if self.mh_filters_checks[check] and bool(value):
                    mh_matched_checks = True
                elif not self.mh_filters_checks[check] and not value:
                    mh_matched_checks = True
                else:
                    mh_matched_checks_all_checks = False

        # Associations
        context_associations = self.associations()

        # Add to output
        mh_values_checks.update(
            {"associations": context_associations, "config": context_config}
        )

        # All checks needs to be matched
        if not mh_matched_checks_all_checks and mode == "all":
            mh_matched_checks = False

        return mh_values_checks, mh_matched_checks

    def execute_drilled_metachecks(self):
        # Optimize drilled metachecks by keeping a cache of drilled resources
        self.drilled_cache = {}

        def execute(resources, MetaCheck):
            for resource in resources:
                if resource not in self.drilled_cache:
                    self.logger.info(
                        "Running Drilled MetaChecks for resource {} from resource: {}".format(
                            resource, self.resource_arn
                        )
                    )
                    try:
                        resource_drilled = MetaCheck(
                            self.logger,
                            self.finding,
                            False,
                            self.sess,
                            drilled=resource,
                        )
                        resource_drilled_output = (
                            resource_drilled.output_checks_drilled()
                        )
                        resources[resource] = resource_drilled_output
                        self.drilled_cache[resource] = resource_drilled_output

                        # Double Drill (IAM Roles >> IAM Policies)
                        if (
                            hasattr(self, "iam_roles")
                            and self.iam_roles
                            and hasattr(resource_drilled, "iam_policies")
                            and resource_drilled.iam_policies
                        ):
                            from lib.context.resources.AwsIamPolicy import (
                                Metacheck as IamPolicyMetacheck,
                            )

                            execute(resource_drilled.iam_policies, IamPolicyMetacheck)

                        # Double Drill (Subnets >> Route Table)
                        if (
                            hasattr(self, "subnets")
                            and self.subnets
                            and hasattr(resource_drilled, "route_tables")
                            and resource_drilled.route_tables
                        ):
                            from lib.context.resources.AwsEc2RouteTable import (
                                Metacheck as RouteTableMetacheck,
                            )

                            execute(resource_drilled.route_tables, RouteTableMetacheck)

                    except (AttributeError, Exception) as err:
                        if "should return None" in str(err):
                            self.logger.info(
                                "Not Found Drilled resource %s from resource: %s",
                                resource,
                                self.resource_arn,
                            )
                        else:
                            self.logger.error(
                                "Error Running Drilled MetaChecks for resource %s from resource: %s - %s",
                                resource,
                                self.resource_arn,
                                err,
                            )
                        resources[resource] = False
                        self.drilled_cache[resource] = False
                else:
                    self.logger.info(
                        "Ignoring (already checked) Drilled MetaChecks for resource {} from resource: {}".format(
                            resource, self.resource_arn
                        )
                    )
                    resources[resource] = self.drilled_cache[resource]

        # Security Groups
        if hasattr(self, "security_groups") and self.security_groups:
            from lib.context.resources.AwsEc2SecurityGroup import (
                Metacheck as SecurityGroupMetacheck,
            )

            execute(self.security_groups, SecurityGroupMetacheck)

        # IAM Roles
        if hasattr(self, "iam_roles") and self.iam_roles:
            from lib.context.resources.AwsIamRole import Metacheck as IamRoleMetacheck

            execute(self.iam_roles, IamRoleMetacheck)

        # IAM Policies
        if hasattr(self, "iam_policies") and self.iam_policies:
            from lib.context.resources.AwsIamPolicy import (
                Metacheck as IamPolicyMetacheck,
            )

            execute(self.iam_policies, IamPolicyMetacheck)

        # AutoScaling Groups
        if hasattr(self, "autoscaling_groups") and self.autoscaling_groups:
            from lib.context.resources.AwsAutoScalingAutoScalingGroup import (
                Metacheck as AwsAutoScalingAutoScalingGroupMetacheck,
            )

            execute(self.autoscaling_groups, AwsAutoScalingAutoScalingGroupMetacheck)

        # Volumes
        if hasattr(self, "volumes") and self.volumes:
            from lib.context.resources.AwsEc2Volume import Metacheck as VolumeMetacheck

            execute(self.volumes, VolumeMetacheck)

        # VPC
        if hasattr(self, "vpcs") and self.vpcs:
            from lib.context.resources.AwsEc2Vpc import Metacheck as VpcMetacheck

            execute(self.vpcs, VpcMetacheck)

        # Subnets
        if hasattr(self, "subnets") and self.subnets:
            from lib.context.resources.AwsEc2Subnet import Metacheck as SubnetMetacheck

            execute(self.subnets, SubnetMetacheck)

        # Route Tables
        if hasattr(self, "route_tables") and self.route_tables:
            from lib.context.resources.AwsEc2RouteTable import (
                Metacheck as RouteTableMetacheck,
            )

            execute(self.route_tables, RouteTableMetacheck)

        # Api Gateway V2 Api
        if hasattr(self, "api_gwv2_apis") and self.api_gwv2_apis:
            from lib.context.resources.AwsApiGatewayV2Api import (
                Metacheck as ApiGatewayV2ApiMetacheck,
            )

            execute(self.api_gwv2_apis, ApiGatewayV2ApiMetacheck)

    def output_checks_drilled(self):
        mh_values_checks = {}
        for check in self.checks():
            hndl = getattr(self, check)()
            mh_values_checks.update({check: hndl})

        return mh_values_checks
