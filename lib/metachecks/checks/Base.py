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

        # We keep a dictionary so we don't scan a same resource twice
        self.route_tables_drilled = {}
        self.subnets_drilled = {}

        # Security Groups
        if hasattr(self, "security_groups") and self.security_groups:
            from lib.metachecks.checks.AwsEc2SecurityGroup import (
                Metacheck as SecurityGroupMetacheck,
            )

            for sg in self.security_groups:
                self.logger.info(
                    "Running Drilled MetaChecks for resource {} for security group: {}".format(
                        self.resource_arn, sg
                    )
                )
                sg_drilled = SecurityGroupMetacheck(
                    self.logger, self.finding, True, False, self.sess, drilled=sg
                )
                self.security_groups[sg] = sg_drilled.output_checks_drilled()

        # IAM Roles
        if hasattr(self, "iam_roles") and self.iam_roles:
            from lib.metachecks.checks.AwsIamRole import Metacheck as IamRoleMetacheck

            for iam_role in self.iam_roles:
                self.logger.info(
                    "Running Drilled MetaChecks for resource {} for IAM role: {}".format(
                        self.resource_arn, iam_role
                    )
                )
                iam_role_drilled = IamRoleMetacheck(
                    self.logger, self.finding, True, False, self.sess, drilled=iam_role
                )
                self.iam_roles[iam_role] = iam_role_drilled.output_checks_drilled()

            # IAM Roles >> IAM Policies
            if (
                hasattr(iam_role_drilled, "iam_policies")
                and iam_role_drilled.iam_policies
            ):
                from lib.metachecks.checks.AwsIamPolicy import (
                    Metacheck as IamPolicyMetacheck,
                )

                for iam_policy in iam_role_drilled.iam_policies:
                    self.logger.info(
                        "Running Drilled MetaChecks for resource {} for IAM policy: {}".format(
                            self.resource_arn, iam_policy
                        )
                    )
                    iam_policy_drilled = IamPolicyMetacheck(
                        self.logger,
                        self.finding,
                        True,
                        False,
                        self.sess,
                        drilled=iam_policy,
                    )
                    iam_role_drilled.iam_policies[
                        iam_policy
                    ] = iam_policy_drilled.output_checks_drilled()

        # IAM Policies
        if hasattr(self, "iam_policies") and self.iam_policies:
            from lib.metachecks.checks.AwsIamPolicy import (
                Metacheck as IamPolicyMetacheck,
            )

            for iam_policy in self.iam_policies:
                self.logger.info(
                    "Running Drilled MetaChecks for resource {} for IAM policy: {}".format(
                        self.resource_arn, iam_policy
                    )
                )
                iam_policy_drilled = IamPolicyMetacheck(
                    self.logger,
                    self.finding,
                    True,
                    False,
                    self.sess,
                    drilled=iam_policy,
                )
                self.iam_policies[
                    iam_policy
                ] = iam_policy_drilled.output_checks_drilled()

        # AutoScaling Groups
        if hasattr(self, "autoscaling_group") and self.autoscaling_group:
            from lib.metachecks.checks.AwsAutoScalingAutoScalingGroup import (
                Metacheck as AwsAutoScalingAutoScalingGroupMetacheck,
            )

            for autoscaling_group in self.autoscaling_group:
                self.logger.info(
                    "Running Drilled MetaChecks for resource {} for AutoScaling Group: {}".format(
                        self.resource_arn, autoscaling_group
                    )
                )
                autoscaling_group_drilled = AwsAutoScalingAutoScalingGroupMetacheck(
                    self.logger,
                    self.finding,
                    True,
                    False,
                    self.sess,
                    drilled=autoscaling_group,
                )
                self.autoscaling_group[
                    autoscaling_group
                ] = autoscaling_group_drilled.output_checks_drilled()

        # Volumes
        if hasattr(self, "volumes") and self.volumes:
            from lib.metachecks.checks.AwsEc2Volume import Metacheck as VolumeMetacheck

            for volume in self.volumes:
                self.logger.info(
                    "Running Drilled MetaChecks for resource {} for Volume: {}".format(
                        self.resource_arn, volume
                    )
                )
                volume_drilled = VolumeMetacheck(
                    self.logger, self.finding, True, False, self.sess, drilled=volume
                )
                self.volumes[volume] = volume_drilled.output_checks_drilled()

        # VPC
        if hasattr(self, "vpcs") and self.vpcs:
            from lib.metachecks.checks.AwsEc2Vpc import Metacheck as VpcMetacheck

            for vpc in self.vpcs:
                self.logger.info(
                    "Running Drilled MetaChecks for resource {} for Route Table: {}".format(
                        self.resource_arn, vpc
                    )
                )
                vpc_drilled = VpcMetacheck(
                    self.logger, self.finding, True, False, self.sess, drilled=vpc
                ).output_checks_drilled()
                self.vpcs[vpc] = vpc_drilled

        # Subnets
        if hasattr(self, "subnets") and self.subnets:
            from lib.metachecks.checks.AwsEc2RouteTable import (
                Metacheck as RouteTableMetacheck,
            )
            from lib.metachecks.checks.AwsEc2Subnet import Metacheck as SubnetMetacheck

            for subnet in self.subnets:
                if subnet in self.subnets_drilled:
                    self.logger.info(
                        "Ignoring (already executed) Drilled MetaChecks for resource {} for Subnet: {}".format(
                            self.resource_arn, subnet
                        )
                    )
                    subnet_drilled_output = self.subnets_drilled[subnet]
                else:
                    self.logger.info(
                        "Running Drilled MetaChecks for resource {} for Subnet: {}".format(
                            self.resource_arn, subnet
                        )
                    )
                    subnet_drilled = SubnetMetacheck(
                        self.logger,
                        self.finding,
                        True,
                        False,
                        self.sess,
                        drilled=subnet,
                    )
                    subnet_drilled_output = subnet_drilled.output_checks_drilled()
                    self.subnets_drilled[subnet] = subnet_drilled_output
                # Add the drilled subnet
                self.subnets[subnet] = subnet_drilled_output

                # Subnets >> Route Tables
                if (
                    hasattr(subnet_drilled, "route_tables")
                    and subnet_drilled.route_tables
                ):

                    for route_table in subnet_drilled.route_tables:
                        # Check if we already scan this resource
                        if route_table in self.route_tables_drilled:
                            self.logger.info(
                                "Ignoring (already executed) Drilled MetaChecks for resource {} for Route Table: {}".format(
                                    subnet_drilled.resource_arn, route_table
                                )
                            )
                            route_table_drilled = self.route_tables_drilled[route_table]
                        else:
                            self.logger.info(
                                "Running Drilled MetaChecks for resource {} for Route Table: {}".format(
                                    subnet_drilled.resource_arn, route_table
                                )
                            )
                            route_table_drilled = RouteTableMetacheck(
                                self.logger,
                                self.finding,
                                True,
                                False,
                                self.sess,
                                drilled=route_table,
                            ).output_checks_drilled()
                            self.route_tables_drilled[route_table] = route_table_drilled
                        # Add the drilled route table to the subnet
                        subnet_drilled.route_tables[route_table] = route_table_drilled

        # Route Tables
        if hasattr(self, "route_tables") and self.route_tables:
            from lib.metachecks.checks.AwsEc2RouteTable import (
                Metacheck as RouteTableMetacheck,
            )

            for route_table in self.route_tables:
                self.logger.info(
                    "Running Drilled MetaChecks for resource {} for Route Table: {}".format(
                        self.resource_arn, route_table
                    )
                )
                route_table_drilled = RouteTableMetacheck(
                    self.logger,
                    self.finding,
                    True,
                    False,
                    self.sess,
                    drilled=route_table,
                ).output_checks_drilled()
                self.route_tables[route_table] = route_table_drilled

    def output_checks_drilled(self):
        mh_values_checks = {}
        for check in self.checks():
            hndl = getattr(self, check)()
            mh_values_checks.update({check: hndl})

        return mh_values_checks
