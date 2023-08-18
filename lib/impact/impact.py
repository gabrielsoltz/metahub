from pathlib import Path

import yaml


class Impact:
    def __init__(self):
        self.impact_config = self.load_impact()
        self.validate_config()

    def validate_config(self):
        for property in self.impact_config:
            property_values = self.impact_config[property]["values"]
            property_weight = self.impact_config[property]["weight"]
            if property_weight is not int:
                return False
            for value in property_values:
                for value_key, value_data in value.items():
                    score = value_data["score"]
                    matchs = value_data["matchs"]
                    if score is not int:
                        return False

    def load_impact(self):
        path_yaml_impact = "lib/impact/impact.yaml"
        try:
            yaml_to_dict = yaml.safe_load(Path(path_yaml_impact).read_text())
        except (yaml.scanner.ScannerError, FileNotFoundError) as err:
            yaml_to_dict = False
        return yaml_to_dict

    def check_match(self, match_type, match, finding):
        """match_type: metachecks/metatags/metaaccount"""
        """ match: {key: value} """
        for resource_key, value in finding.items():
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

    def check_property(self, property_values, finding):
        for value in property_values:
            for value_key, value_data in value.items():
                score = value_data["score"]
                matchs = value_data["matchs"]
                for match in matchs:
                    for match_type, matchs_data in match.items():
                        for match_item in matchs_data:
                            if self.check_match(match_type, match_item, finding):
                                return value_key, score
        return False

    def get_findings_score(self, finding):
        findings_value = {
            "CRITICAL": 4,
            "HIGH": 3.5,
            "MEDIUM": 2,
            "LOW": 1,
            "INFORMATIONAL": 0,
        }
        findings_score = 0
        for f in finding["findings"]:
            for k, v in f.items():
                # Only ACTIVE findings
                if v.get("RecordState") == "ACTIVE":
                    findings_score_max = max(
                        findings_score, findings_value.get(v.get("SeverityLabel"))
                    )
                    findings_score_sum = findings_score + findings_value.get(
                        v.get("SeverityLabel")
                    )
        findings_score_avg = findings_score_sum / len(finding["findings"])
        findings_score_max_avg = findings_score_max / max(findings_value.values())
        return findings_score_max_avg

    def get_meta_score(self, score):
        weight_total = 0
        value_total = 0
        for key, value in score.items():
            weight = score[key]["weight"]
            value = score[key]["value"]
            if value != "-":
                weight_total += weight
                value_total += weight * value
        if weight_total == 0:
            impact_score = "n/a"
        else:
            impact_score = (value_total / weight_total) * 100
        return impact_score

    def get_impact(self, finding):
        impact = {}
        score = {}
        for property in self.impact_config:
            property_values = self.impact_config[property]["values"]
            property_weight = self.impact_config[property]["weight"]
            checked_property = self.check_property(property_values, finding)
            if checked_property is not False:
                impact[property] = checked_property[0]
                score[property] = {
                    "weight": property_weight,
                    "value": checked_property[1],
                }
            else:
                impact[property] = "n/a"
                score[property] = {"weight": property_weight, "value": "-"}
        impact["findings_score"] = self.get_findings_score(finding)
        impact["meta_score"] = self.get_meta_score(score)
        if impact["meta_score"] != "n/a":
            impact["score"] = impact["findings_score"] * impact["meta_score"]
        else:
            impact["score"] = impact["findings_score"] * 100
        impact["score"] = round(impact["score"], 2)
        return impact
