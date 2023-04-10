from typing import List, Dict


class ReportCreator():
    """ This class uses the configured CVE visitor to visit each entry in a data
        structure containing all discovered CVEs to generate a report. Each visitor
        implementation outputs a report in its own specific format (e.g. HTMLReportVisitor
        visits each entry to generate an HTML report). The data structure organizes CVEs by
        package file type (source) and whether each a CVE has been seen by previous
        runs of CVE Tracker. Those CVEs that were not seen previously are listed as new. """

    def __init__(self, report_name: str, visitor,
                 dependencies: List[Dict[str, str]], notifier=None):

        self._visitor = visitor
        self._report_name = report_name
        self._report_file = open(report_name, 'w')
        self._notifier = notifier
        self._dependencies = dependencies

    def create_report(self, relevant_cves: Dict[str, Dict[str, List[str]]]):
        self._report_file.write(self._visitor.start_visiting())
        new_cves = []

        for module_source in relevant_cves:
            new_cves.extend(relevant_cves[module_source]['New'])

            self._report_file.write(self._visitor.visit_source(module_source,
                                                               relevant_cves[module_source]['New'],
                                                               relevant_cves[module_source]['Old']))

        self._report_file.write(self._visitor.finished_visiting(self._dependencies))
        self._report_file.close()

        if new_cves and self._notifier:
            self._notifier.send_notification(new_cves, self._report_name)
