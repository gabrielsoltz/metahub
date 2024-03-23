import lib.main
from lib.helpers import get_logger


def lambda_handler(event, context):
    logger = get_logger("INFO")

    # Add your custom options here (e.g. Only Critical: ["--sh-filters", "SeverityLabel=CRITICAL"])
    # Only used if triggering lambda manually, not from Security Hub Custom Actions
    custom_options = []

    # Actions the lambda will execute, if you don't need actions, keep this list empty
    # Example, for enriching findings:
    # actions = [
    #     "--enrich-findings",
    #     "--no-actions-confirmation",
    # ]
    actions = []

    # These are the minimum options required to run the Lambda, don't change this
    lambda_options = [
        "--output-modes",
        "lambda",
        "--no-banners",
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
            resource_id = finding.get("Resources")[0].get("Id")
            logger.info("Security Hub Finding: %s", finding_id)
            custom_options = []
            # Search by ResoureId
            lambda_options.extend(
                ["--sh-filters", f"ResourceId={resource_id}", "RecordState=ACTIVE"]
            )
            # Search by FindingId
            # lambda_options.extend(["--sh-filters", f"Id={finding_id}"])

    options = lambda_options + actions + custom_options

    logger.info("Executing with options: %s", options)
    execution_result = lib.main.main(options)
    return execution_result
