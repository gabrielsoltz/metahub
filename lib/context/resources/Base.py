class ContextBase:
    def __init__(
        self,
        logger,
        finding,
        mh_filters_config,
        sess,
        drilled=False,
    ):
        self.logger = logger

    def output_checks(self):
        """
        return mh_values_checks: values dictionary.
        return mh_matched_checks: True if mh-filters-checks matchs one of metachecks the values
        """

        # mode = "atleast1"
        mode = "all"

        mh_values_checks = {}
        # If there is no filters, we force match to True
        mh_matched_checks = False if self.mh_filters_config else True
        # All Checks needs to be matched
        mh_matched_checks_all_checks = True

        # Config
        context_config = self.checks()
        context_associations = self.associations()
        context_all = {**context_config, **context_associations}
        for check, value in context_all.items():
            if check in self.mh_filters_config:
                self.logger.info(
                    "Evaluating Config filter ("
                    + check
                    + "). Expected: "
                    + str(self.mh_filters_config[check])
                    + " Found: "
                    + str(bool(value))
                )
                if self.mh_filters_config[check] and bool(value):
                    mh_matched_checks = True
                elif not self.mh_filters_config[check] and not value:
                    mh_matched_checks = True
                else:
                    mh_matched_checks_all_checks = False

        # Add to output
        mh_values_checks.update(
            {"associations": context_associations, "config": context_config}
        )

        # All checks needs to be matched
        if not mh_matched_checks_all_checks and mode == "all":
            mh_matched_checks = False

        return mh_values_checks, mh_matched_checks

    def execute_drilled_metachecks(self, cached_associated_resources):
        # Optimize drilled context by keeping a cache of drilled resources
        self.drilled_cache = cached_associated_resources

        def execute(r, MetaCheck):
            if r not in self.drilled_cache:
                self.logger.info(
                    "Running Drilled Context for resource {} from resource: {}".format(
                        r, self.resource_arn
                    )
                )
                try:
                    resource_drilled = MetaCheck(
                        self.logger,
                        self.finding,
                        False,
                        self.sess,
                        drilled=r,
                    )
                    resource_drilled_output = resource_drilled.output_checks_drilled()
                    self.drilled_cache[r] = resource_drilled_output

                except (AttributeError, Exception) as err:
                    if "should return None" in str(err):
                        self.logger.info(
                            "Not Found Drilled resource %s from resource: %s",
                            r,
                            self.resource_arn,
                        )
                    else:
                        self.logger.error(
                            "Error Running Drilled MetaChecks for resource %s from resource: %s - %s",
                            r,
                            self.resource_arn,
                            err,
                        )
                    resource_drilled = False
                    resource_drilled_output = False
                    self.drilled_cache[r] = False
            else:
                self.logger.info(
                    "Ignoring (already checked) Drilled MetaChecks for resource {} from resource: {}".format(
                        r, self.resource_arn
                    )
                )
                resource_drilled = False
                resource_drilled_output = self.drilled_cache[r]

            return resource_drilled_output, resource_drilled

        def check_associated_resources(resource, level):
            # print ("Level: {}, Resource: {}".format(level, resource.resource_arn))

            # Security Groups
            if (
                hasattr(resource, "iam_users")
                and resource.iam_users
                and self.resource_type != "AwsIamUser"
            ):
                from lib.context.resources.AwsIamUser import (
                    Metacheck as AwsIamUserMetacheck,
                )

                for r, v in list(resource.iam_users.items()):
                    resource_drilled_output, resource_drilled = execute(
                        r, AwsIamUserMetacheck
                    )
                    resource.iam_users[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

            # Security Groups
            if (
                hasattr(resource, "security_groups")
                and resource.security_groups
                and self.resource_type != "AwsEc2SecurityGroup"
            ):
                from lib.context.resources.AwsEc2SecurityGroup import (
                    Metacheck as SecurityGroupMetacheck,
                )

                for r, v in list(resource.security_groups.items()):
                    resource_drilled_output, resource_drilled = execute(
                        r, SecurityGroupMetacheck
                    )
                    resource.security_groups[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

            # IAM Roles
            if (
                hasattr(resource, "iam_roles")
                and resource.iam_roles
                and self.resource_type != "AwsIamRole"
            ):
                from lib.context.resources.AwsIamRole import (
                    Metacheck as AwsIamRoleMetaCheck,
                )

                for r, v in list(resource.iam_roles.items()):
                    resource_drilled_output, resource_drilled = execute(
                        r, AwsIamRoleMetaCheck
                    )
                    resource.iam_roles[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

            # IAM Policies
            if (
                hasattr(resource, "iam_policies")
                and resource.iam_policies
                and self.resource_type != "AwsIamPolicy"
            ):
                from lib.context.resources.AwsIamPolicy import (
                    Metacheck as IamPolicyMetacheck,
                )

                for r, v in list(resource.iam_policies.items()):
                    resource_drilled_output, resource_drilled = execute(
                        r, IamPolicyMetacheck
                    )
                    resource.iam_policies[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

            # AutoScaling Groups
            if (
                hasattr(resource, "autoscaling_groups")
                and resource.autoscaling_groups
                and self.resource_type != "AwsAutoScalingAutoScalingGroup"
            ):
                from lib.context.resources.AwsAutoScalingAutoScalingGroup import (
                    Metacheck as AwsAutoScalingAutoScalingGroupMetacheck,
                )

                for r, v in list(resource.autoscaling_groups.items()):
                    resource_drilled_output, resource_drilled = execute(
                        r, AwsAutoScalingAutoScalingGroupMetacheck
                    )
                    resource.autoscaling_groups[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

            # Volumes
            if (
                hasattr(resource, "volumes")
                and resource.volumes
                and self.resource_type != "AwsEc2Volume"
            ):
                from lib.context.resources.AwsEc2Volume import (
                    Metacheck as VolumeMetacheck,
                )

                for r, v in list(resource.volumes.items()):
                    resource_drilled_output, resource_drilled = execute(
                        r, VolumeMetacheck
                    )
                    resource.volumes[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

            # VPC
            if (
                hasattr(resource, "vpcs")
                and resource.vpcs
                and self.resource_type != "AwsEc2Vpc"
            ):
                from lib.context.resources.AwsEc2Vpc import Metacheck as VpcMetacheck

                for r, v in list(resource.vpcs.items()):
                    resource_drilled_output, resource_drilled = execute(r, VpcMetacheck)
                    resource.vpcs[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

            # Subnets
            if (
                hasattr(resource, "subnets")
                and resource.subnets
                and self.resource_type != "AwsEc2Subnet"
            ):
                from lib.context.resources.AwsEc2Subnet import (
                    Metacheck as SubnetMetacheck,
                )

                for r, v in list(resource.subnets.items()):
                    resource_drilled_output, resource_drilled = execute(
                        r, SubnetMetacheck
                    )
                    resource.subnets[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

            # Route Tables
            if (
                hasattr(resource, "route_tables")
                and resource.route_tables
                and self.resource_type != "AwsEc2RouteTable"
            ):
                from lib.context.resources.AwsEc2RouteTable import (
                    Metacheck as RouteTableMetacheck,
                )

                for r, v in list(resource.route_tables.items()):
                    resource_drilled_output, resource_drilled = execute(
                        r, RouteTableMetacheck
                    )
                    resource.route_tables[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

            # Api Gateway V2 Api
            if (
                hasattr(resource, "api_gwv2_apis")
                and resource.api_gwv2_apis
                and self.resource_type != "AwsApiGatewayV2Api"
            ):
                from lib.context.resources.AwsApiGatewayV2Api import (
                    Metacheck as ApiGatewayV2ApiMetacheck,
                )

                for r, v in list(resource.api_gwv2_apis.items()):
                    resource_drilled_output, resource_drilled = execute(
                        r, ApiGatewayV2ApiMetacheck
                    )
                    resource.api_gwv2_apis[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

            # Instances
            if (
                hasattr(resource, "instances")
                and resource.instances
                and self.resource_type != "AwsEc2Instance"
            ):
                from lib.context.resources.AwsEc2Instance import (
                    Metacheck as AwsEc2InstanceMetacheck,
                )

                for r, v in list(resource.instances.items()):
                    resource_drilled_output, resource_drilled = execute(
                        r, AwsEc2InstanceMetacheck
                    )
                    resource.instances[r] = resource_drilled_output
                    self.all_associations[r] = resource_drilled_output
                    if level < 1 and resource_drilled:
                        check_associated_resources(resource_drilled, level + 1)

        self.all_associations = {}
        check_associated_resources(self, 0)

        return self.all_associations

    def output_checks_drilled(self):
        mh_values_checks = {}
        context_config = self.checks()
        context_associations = self.associations()
        mh_values_checks.update(
            {"associations": context_associations, "config": context_config}
        )
        return mh_values_checks
