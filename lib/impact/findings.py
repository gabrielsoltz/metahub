from lib.config.configuration import findings_severity_value


class Findings:
    def __init__(self, logger):
        self.logger = logger

    def get_findings_score(self, resource_arn, resource_values):
        self.logger.info("Calculating impact findings score for resource")

        # Initialize the findings score to zero
        findings_score = 0
        count_active_findings = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFORMATIONAL": 0,
            "UNDEFINED": 0,
        }

        # Iterate through each finding in the resource
        for f in resource_values["findings"]:
            for k, v in f.items():
                # Check if the finding is active
                if v.get("RecordState") == "ACTIVE":
                    # Get the severity value for the finding
                    single_finding_severity = findings_severity_value.get(
                        v.get("SeverityLabel")
                    )
                    # Get the single finding score
                    single_finding_score = single_finding_severity / max(
                        findings_severity_value.values()
                    )
                    # Sum the single finding score to the findings score
                    findings_score += single_finding_score
                    # Count the number of active findings per severity
                    count_active_findings[v.get("SeverityLabel")] += 1

        # Ensure the findings score does not exceed 1
        if findings_score > 1:
            findings_score = 1

        return {findings_score: {"findings": count_active_findings}}
