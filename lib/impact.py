from pathlib import Path

import yaml


class Impact:
    def __init__(self, logger):
        self.logger = logger
        self.impact_config = self.load_impact_config()
        self.findings_severity_value = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 1,
            "LOW": 0.5,
            "INFORMATIONAL": 0,
        }

    def load_impact_config(self):
        path_yaml_impact = "lib/config/impact.yaml"
        try:
            yaml_to_dict = yaml.safe_load(Path(path_yaml_impact).read_text())
            if not self.validate_config(yaml_to_dict):
                yaml_to_dict = False
        except (yaml.scanner.ScannerError, FileNotFoundError) as err:
            self.logger.error("Error loading impact.yaml: %s", err)
            yaml_to_dict = False
        return yaml_to_dict

    def validate_config(self, config):
        for property in config:
            property_values = config[property]["values"]
            property_weight = config[property]["weight"]
            if not isinstance(property_weight, (int, float)):
                self.logger.error(
                    "Error validating impact.yaml: weight is not int %s",
                    property_weight,
                )
                return False
            for value in property_values:
                for value_key, value_data in value.items():
                    score = value_data["score"]
                    if not isinstance(score, (int, float)):
                        self.logger.error(
                            "Error validating impact.yaml: score is not int %s",
                            property_weight,
                        )
                        return False
                    if score > 1:
                        self.logger.error(
                            "Error validating impact.yaml: score is greater than 1 %s",
                            property_weight,
                        )
                        return False
        return True

    def check_match(self, match_type, match, resource):
        # Check if the value match the resource
        """match_type: metachecks/metatags/metaaccount"""
        """ match: {key: value} """
        for resource_key, value in resource.items():
            if resource_key == match_type and value:
                for match_key, match_value in match.items():
                    meta_output = value.get(match_key)
                    if meta_output is not None:
                        if match_type == "metachecks":
                            if bool(meta_output) == bool(match_value):
                                return True
                        else:
                            if meta_output == match_value:
                                return True
        return False

    def check_property(self, property_values, resource):
        # Check if the property is applicable to the resource
        for value in property_values:
            for value_key, value_data in value.items():
                score = value_data["score"]
                matchs = value_data["matchs"]
                for match in matchs:
                    for match_type, matchs_data in match.items():
                        for match_item in matchs_data:
                            if self.check_match(match_type, match_item, resource):
                                return value_key, score
        return False

    def get_findings_score(self, resource):
        self.logger.info("Calculating impact findings score for resource")

        # Initialize the findings score to zero
        findings_score = 0

        # Iterate through each finding in the resource
        for f in resource["findings"]:
            for k, v in f.items():
                # Check if the finding is active
                if v.get("RecordState") == "ACTIVE":
                    # Get the severity value for the finding
                    single_finding_severity = self.findings_severity_value.get(
                        v.get("SeverityLabel")
                    )
                    # Get the single finding score
                    single_finding_score = single_finding_severity / max(
                        self.findings_severity_value.values()
                    )
                    # Sum the single finding score to the findings score
                    findings_score += single_finding_score

        # Ensure the findings score does not exceed 1
        if findings_score > 1:
            findings_score = 1

        return findings_score

    def get_meta_score(self, resource):
        self.logger.info("Calculating impact meta score for resource")

        # Initialize variables to track the meta score details and context
        meta_score_details = {}
        weight_total = 0
        score_total = 0
        context = False

        # Iterate through each property in the impact configuration for the resource
        for property in self.impact_config:
            # Get the weight and values for each the property from the configuration
            property_values = self.impact_config[property]["values"]
            property_weight = self.impact_config[property]["weight"]
            # Check the property against the finding
            checked_property = self.check_property(property_values, resource)
            # If the property check is not False (i.e., it has a value),
            # record the weight, value, and calculated score for this property
            if checked_property is not False:
                meta_score_details[property] = {
                    "weight": property_weight,
                    "value": checked_property[0],
                    "score": checked_property[1],
                }
                # Update the total weight and value based on this property
                weight_total += property_weight
                score_total += property_weight * checked_property[1]
                # Flag there is some context for the resource
                context = True
            else:
                # If the property check is False, indicate that it's not applicable
                meta_score_details[property] = {
                    "weight": property_weight,
                    "value": "n/a",
                    "score": "-",
                }

        # Calculate the meta score based on the weighted values if there is context
        if not context:
            meta_score = "n/a"
        else:
            meta_score = (score_total / weight_total) * 100

        self.logger.info(
            "Impact Meta Score %s, details:: %s", meta_score, meta_score_details
        )

        return meta_score

    def get_impact(self, resource):
        if not self.impact_config:
            return False

        # Create a dictionary to store the impact scores
        impact = {}

        # Calculate the findings score using the get_findings_score method
        impact["findings_score"] = self.get_findings_score(resource)
        # Calculate the meta score using the get_meta_score method
        impact["meta_score"] = self.get_meta_score(resource)

        # Check if the meta score is not "n/a" (i.e., there's context)
        if impact["meta_score"] != "n/a":
            # Calculate the overall impact score as the product of findings_score and meta_score
            impact_score = impact["findings_score"] * impact["meta_score"]
        else:
            # If there's no context, calculate the impact score as findings_score * 100
            impact_score = impact["findings_score"] * 100

        # Round the impact score to 2 decimal places
        impact_score = round(impact_score, 2)

        # Check if the number has a decimal part
        if impact_score % 1 == 0:
            impact_score = int(impact_score)  # Return the integer part

        impact["Impact"] = impact_score

        # Return the dictionary containing impact scores
        return impact
