from lib.findings import count_mh_findings
from lib.helpers import confirm_choice, print_table, print_title_line


class Actions:
    def __init__(self, logger, args, mh_findings, sh):
        self.logger = logger
        self.args = args
        self.mh_findings = mh_findings
        self.sh = sh

    def update_findings(self, update_filters):
        UPProcessedFindings = []
        UPUnprocessedFindings = []
        print_title_line("Update Findings", banners=self.args.banners)
        print_table(
            "Findings to update: ",
            str(count_mh_findings(self.mh_findings)),
            banners=self.args.banners,
        )
        print_table(
            "Update: ", str(self.args.update_findings), banners=self.args.banners
        )

        # Lambda output
        if "lambda" in self.args.output_modes:
            print(
                "Updating findings: ",
                str(count_mh_findings(self.mh_findings)),
                "with:",
                str(self.args.update_findings),
            )

        if self.mh_findings and confirm_choice(
            "Are you sure you want to update all findings?",
            self.args.actions_confirmation,
        ):
            update_multiple = self.sh.update_findings_workflow(
                self.mh_findings, update_filters
            )
            for update in update_multiple:
                for ProcessedFinding in update["ProcessedFindings"]:
                    self.logger.info("Updated Finding : " + ProcessedFinding["Id"])
                    UPProcessedFindings.append(ProcessedFinding)
                for UnprocessedFinding in update["UnprocessedFindings"]:
                    self.logger.error(
                        "Error Updating Finding: "
                        + UnprocessedFinding["FindingIdentifier"]["Id"]
                        + " Error: "
                        + UnprocessedFinding["ErrorMessage"]
                    )
                    UPUnprocessedFindings.append(UnprocessedFinding)

        self.print_processed(UPProcessedFindings, UPUnprocessedFindings)

    def enrich_findings(self):
        ENProcessedFindings = []
        ENUnprocessedFindings = []
        print_title_line("Enrich Findings", banners=self.args.banners)
        print_table(
            "Findings to enrich: ",
            str(count_mh_findings(self.mh_findings)),
            banners=self.args.banners,
        )

        # Lambda output
        if "lambda" in self.args.output_modes:
            print("Enriching findings: ", str(count_mh_findings(self.mh_findings)))

        if self.mh_findings and confirm_choice(
            "Are you sure you want to enrich all findings?",
            self.args.actions_confirmation,
        ):
            update_multiple = self.sh.update_findings_meta(self.mh_findings)
            for update in update_multiple:
                for ProcessedFinding in update["ProcessedFindings"]:
                    self.logger.info("Updated Finding : " + ProcessedFinding["Id"])
                    ENProcessedFindings.append(ProcessedFinding)
                for UnprocessedFinding in update["UnprocessedFindings"]:
                    self.logger.error(
                        "Error Updating Finding: "
                        + UnprocessedFinding["FindingIdentifier"]["Id"]
                        + " Error: "
                        + UnprocessedFinding["ErrorMessage"]
                    )
                    ENUnprocessedFindings.append(UnprocessedFinding)

        self.print_processed(ENProcessedFindings, ENUnprocessedFindings)

    def print_processed(self, processed, unprocessed):
        print_title_line("Results", banners=self.args.banners)
        print_table(
            "ProcessedFindings: ", str(len(processed)), banners=self.args.banners
        )
        print_table(
            "UnprocessedFindings: ", str(len(unprocessed)), banners=self.args.banners
        )
