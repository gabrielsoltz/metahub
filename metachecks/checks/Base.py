class MetaChecksBase():

    def __init__(self):
        pass

    def output_tags(self):
        '''
        return mh_values_tags: MetaTags values dictionary.
        return mh_matched_tags: True if mh-filters-tags match one of the metatags values
        '''

        mh_values_tags = {}
        mh_matched_tags = False if self.mh_filters_tags else True
        if self.tags:
            for tag in self.tags:
                mh_values_tags.update({tag["Key"]: tag["Value"]})
            compare = {k: mh_values_tags[k] for k in mh_values_tags if k in self.mh_filters_tags and mh_values_tags[k] == self.mh_filters_tags[k]}
            self.logger.info(
                "Evaluating MetaTag filter. Expected: "
                + str(self.mh_filters_tags)
                + " Found: "
                + str(bool(compare))
            )
            if self.mh_filters_tags and bool(compare):
                mh_matched_tags = True
        return mh_values_tags, mh_matched_tags

    def output_checks(self):
        '''
        return mh_values_checks: MetaChecks values dictionary.
        return mh_matched_checks: True if mh-filters-checks matchs one of metachecks the values
        '''

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
        if not mh_matched_checks_all_checks:
            mh_matched_checks = False

        return mh_values_checks, mh_matched_checks