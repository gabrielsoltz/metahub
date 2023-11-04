import lib.main
from lib.helpers import get_logger


def lambda_handler(event, context):
    logger = get_logger("INFO")

    # Add your custom options here (e.g. Only Critical: ["--sh-filters", "SeverityLabel=CRITICAL"])

    # - Options for running Lambda from Security Hub Custom Actions
    SH_CUSTOM_OPTIONS = [
        "--enrich-findings",
    ]

    # - Options when running Lambda from any other source
    CUSTOM_OPTIONS = []

    # This are the minimum options required to run the Lambda, don't change this
    LAMBDA_OPTIONS = [
        "--output-modes",
        "lambda",
        "--no-banners",
        "--no-actions-confirmation",
    ]

    # Lambda execution
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
            CUSTOM_OPTIONS = SH_CUSTOM_OPTIONS
            LAMBDA_OPTIONS = [  # You shouldn't need to change this
                "--output-modes",
                "lambda",
                "--no-banners",
                "--sh-filters",
                f"Id={finding_id}",
                "--no-actions-confirmation",
            ]

    OPTIONS = CUSTOM_OPTIONS + LAMBDA_OPTIONS

    logger.info("Executing with options: %s", OPTIONS)
    exec = lib.main.main(OPTIONS)
    return exec
