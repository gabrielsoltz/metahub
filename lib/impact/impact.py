from pathlib import Path

import yaml

from lib.config.configuration import path_yaml_impact
from lib.impact.access import Access
from lib.impact.application import Application
from lib.impact.encryption import Encryption
from lib.impact.environment import Environment
from lib.impact.exposure import Exposure
from lib.impact.findings import Findings
from lib.impact.owner import Owner
from lib.impact.status import Status


class Impact:
    def __init__(self, logger):
        self.logger = logger
        self.impact_config = self.load_impact_config()

    def load_impact_config(self):
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

    def check_property_values_with_resource(
        self, property_name, property_values, impact_dict
    ):
        # Check property with resource and return the matching value and score
        if property_name in impact_dict:
            for value in property_values:
                for value_key, value_data in value.items():
                    if value_key in impact_dict[property_name]:
                        return value_key, value_data["score"]
        return False

    def calculate_properties_score(self, impact_dict):
        self.logger.info("Calculating impact properties score for resource")

        # Initialize variables to track the meta score details and context
        meta_score_details = {}
        weight_total = 0
        score_total = 0
        context = False

        # Iterate through each property in the impact configuration for the resource
        for property in self.impact_config:
            property_name = property
            # Get the weight and values for each the property from the configuration
            property_values = self.impact_config[property]["values"]
            property_weight = self.impact_config[property]["weight"]
            # Check the property against the finding
            checked_property = self.check_property_values_with_resource(
                property_name, property_values, impact_dict
            )
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
            meta_score = score_total / weight_total

        self.logger.info(
            "Impact Meta Score %s, details:: %s", meta_score, meta_score_details
        )

        return meta_score

    def generate_impact_scoring(self, resource_arn, impact_dict):
        self.logger.info("Calculating impact score for resource")
        if not self.impact_config:
            return False

        # Get the findings score from the impact dictionary
        findings_score = float([str(key) for key in impact_dict["findings"].keys()][0])
        # Calculate the impact properties score
        meta_score = self.calculate_properties_score(impact_dict)

        # Check if the meta score is not "n/a" (i.e., there's context)
        if meta_score != "n/a" and meta_score != 0:
            # Calculate the overall impact score as the product of findings_score and meta_score
            impact_score = findings_score * meta_score * 100
        # If meta_score it's 0, let's convert to 0.1 to avoid getting 0 as the impact score
        elif meta_score == 0:
            meta_score = 0.1
            impact_score = findings_score * meta_score * 100
        else:
            # If there's no context, calculate the impact score as findings_score * 100
            impact_score = findings_score * 100

        # Round the impact score to 2 decimal places
        impact_score = round(impact_score, 2)

        # Check if the number has a decimal part
        if impact_score % 1 == 0:
            impact_score = int(impact_score)  # Return the integer part

        # Return the dictionary containing impact scores
        return {impact_score: {}}

    def generate_impact_checks(self, resource_arn, resource_values):
        self.logger.info("Executing Impact Module")
        impact_dict = {
            "exposure": {},
            "access": {},
            "encryption": {},
            "status": {},
            "environment": {},
            "application": {},
            "owner": {},
            "findings": {},
            "score": {},
        }
        impact_dict["exposure"].update(
            Exposure(self.logger).get_exposure(resource_arn, resource_values)
        )
        impact_dict["access"].update(
            Access(self.logger).get_access(resource_arn, resource_values)
        )
        impact_dict["encryption"].update(
            Encryption(self.logger).get_encryption(resource_arn, resource_values)
        )
        impact_dict["status"].update(
            Status(self.logger).get_status(resource_arn, resource_values)
        )
        impact_dict["environment"].update(
            Environment(self.logger).get_environment(resource_arn, resource_values)
        )
        impact_dict["application"].update(
            Application(self.logger).get_application(resource_arn, resource_values)
        )
        impact_dict["owner"].update(
            Owner(self.logger).get_owner(resource_arn, resource_values)
        )
        impact_dict["findings"].update(
            Findings(self.logger).get_findings_score(resource_arn, resource_values)
        )
        impact_dict["score"].update(
            self.generate_impact_scoring(resource_arn, impact_dict)
        )
        return impact_dict
