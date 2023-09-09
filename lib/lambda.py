import lib.main
from lib.helpers import get_logger


def lambda_handler(event, context):
    logger = get_logger("INFO")

    LAMBDA_OPTIONS = ["--output-modes", "lambda", "--no-banners"]
    # Add your custom options here (e.g. ["--sh-filters", "Id=arn::::010101010101", "--meta-checks"])
    CUSTOM_OPTIONS = []
    # Add your custom actions here (e.g. ["--enrich-findings", "--no-actions-confirmation"])
    CUSTOM_ACTIONS = ["--no-actions-confirmation"]

    event_source = event.get("source")
    event_detail_type = event.get("detail-type")
    logger.info("Event Source: %s (%s)", event_source, event_detail_type)

    # Code to handle Security Hub Custom Actions, execution by finding
    if (
        event_source == "aws.securityhub"
        and event_detail_type == "Security Hub Findings - Custom Action"
    ):
        event_detail = event.get("detail")
        action_name = event_detail.get("actionName")
        logger.info("Security Hub Custom Action: %s", action_name)
        for finding in event_detail.get("findings"):
            finding_id = finding.get("Id")
            logger.info("Security Hub Finding: %s", finding_id)
            LAMBDA_OPTIONS = [
                "--output-modes",
                "lambda",
                "--no-banners",
                "--sh-filters",
                f"Id={finding_id}",
            ]
            CUSTOM_OPTIONS = [
                "--meta-checks",
                "--meta-tags",
                "--meta-trails",
                "--meta-account",
            ]
            CUSTOM_ACTIONS = ["--enrich-findings", "--no-actions-confirmation"]

    OPTIONS = LAMBDA_OPTIONS + CUSTOM_OPTIONS + CUSTOM_ACTIONS

    logger.info("Executing with options: %s", OPTIONS)
    exec = lib.main.main(OPTIONS)
    print(exec)
    return exec
