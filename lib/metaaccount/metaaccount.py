from lib.AwsHelpers import get_account_alias, get_account_alternate_contact


def run_metaaccount(finding, mh_role, logger):
    account_id = finding["AwsAccountId"]

    logger.info("Running MetaAccount for Account: %s", account_id)

    account_data = {
        "Alias": get_account_alias(logger, account_id, mh_role),
        "AlternateContact": get_account_alternate_contact(logger, account_id, mh_role),
    }

    return account_data
