class MetaChecksBase:
    def __init__(
        self,
        logger,
        finding,
        metachecks,
        mh_filters_checks,
        sess,
        drilled_down,
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

        mh_matched_checks_all_checks = True
        for check in self.checks():
            hndl = getattr(self, check)()
            mh_values_checks.update({check: hndl})
            if check in self.mh_filters_checks:
                self.logger.info(
                    "Evaluating MetaCheck filter ("
                    + check
                    + "). Expected: "
                    + str(self.mh_filters_checks[check])
                    + " Found: "
                    + str(bool(hndl))
                )
                if self.mh_filters_checks[check] and bool(hndl):
                    mh_matched_checks = True
                elif not self.mh_filters_checks[check] and not hndl:
                    mh_matched_checks = True
                else:
                    mh_matched_checks_all_checks = False

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
                            True,
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
                            from lib.metachecks.checks.AwsIamPolicy import (
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
                            from lib.metachecks.checks.AwsEc2RouteTable import (
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
                            resources[resource] = False
                        else:
                            self.logger.error(
                                "Error Running Drilled MetaChecks for resource %s from resource: %s",
                                resource,
                                self.resource_arn,
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
            from lib.metachecks.checks.AwsEc2SecurityGroup import (
                Metacheck as SecurityGroupMetacheck,
            )

            execute(self.security_groups, SecurityGroupMetacheck)

        # IAM Roles
        if hasattr(self, "iam_roles") and self.iam_roles:
            from lib.metachecks.checks.AwsIamRole import Metacheck as IamRoleMetacheck

            execute(self.iam_roles, IamRoleMetacheck)

        # IAM Policies
        if hasattr(self, "iam_policies") and self.iam_policies:
            from lib.metachecks.checks.AwsIamPolicy import (
                Metacheck as IamPolicyMetacheck,
            )

            execute(self.iam_policies, IamPolicyMetacheck)

        # AutoScaling Groups
        if hasattr(self, "autoscaling_group") and self.autoscaling_group:
            from lib.metachecks.checks.AwsAutoScalingAutoScalingGroup import (
                Metacheck as AwsAutoScalingAutoScalingGroupMetacheck,
            )

            execute(self.autoscaling_group, AwsAutoScalingAutoScalingGroupMetacheck)

        # Volumes
        if hasattr(self, "volumes") and self.volumes:
            from lib.metachecks.checks.AwsEc2Volume import Metacheck as VolumeMetacheck

            execute(self.volumes, VolumeMetacheck)

        # VPC
        if hasattr(self, "vpcs") and self.vpcs:
            from lib.metachecks.checks.AwsEc2Vpc import Metacheck as VpcMetacheck

            execute(self.vpcs, VpcMetacheck)

        # Subnets
        if hasattr(self, "subnets") and self.subnets:
            from lib.metachecks.checks.AwsEc2Subnet import Metacheck as SubnetMetacheck

            execute(self.subnets, SubnetMetacheck)

        # Route Tables
        if hasattr(self, "route_tables") and self.route_tables:
            from lib.metachecks.checks.AwsEc2RouteTable import (
                Metacheck as RouteTableMetacheck,
            )

            execute(self.route_tables, RouteTableMetacheck)

    def output_checks_drilled(self):
        mh_values_checks = {}
        for check in self.checks():
            hndl = getattr(self, check)()
            mh_values_checks.update({check: hndl})

        return mh_values_checks
