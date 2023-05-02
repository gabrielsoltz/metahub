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
        # Security Groups
        if self.security_groups:
            from lib.metachecks.checks.AwsEc2SecurityGroup import (
                Metacheck as SecurityGroupMetacheck,
            )

            for sg in self.security_groups:
                self.logger.info(
                    "Drilling metachecks for security group: {}".format(sg)
                )
                # We only drill down one level, so here we set drilled_down to False
                self.security_groups[sg] = SecurityGroupMetacheck(
                    self.logger, self.finding, True, False, self.sess, False, drilled=sg
                ).output_checks_drilled()

    def output_checks_drilled(self):
        mh_values_checks = {}
        for check in self.checks():
            hndl = getattr(self, check)()
            mh_values_checks.update({check: hndl})

        return mh_values_checks
