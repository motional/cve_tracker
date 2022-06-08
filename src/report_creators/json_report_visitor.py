from typing import List, Dict
from src.report_creators.cve_visitor import CveVisitor




def create_json_cve_entry(cve: Dict[str, str]) -> str:
    json_cve_source = '        {\n             \"MODULE_SOURCE\": \"' + cve['MODULE_SOURCE'] + '\",\n'
    json_cve_id = '             \"ID\": \"' + cve['ID'] + '\",\n'
    json_module_name = '             \"ModuleName\": \"' + cve['ModuleName'] + '\",\n'
    json_version = '             \"Version\": \"' + cve['Version'] + '\",\n'
    json_vendor_url = '             \"URL\": \"' + cve['URL'] + '\",\n'
    json_cve_description = '             \"Description\": \"' + cve['Description'].replace('"', '') + '\",\n'
    json_cve_base_score = '             \"BaseScore\": \"' + cve['BaseScore'] + '\",\n'
    json_cve_cvss_vector = '             \"CVSSVector\": \"' + cve['CVSSVector'] + '\",\n'
    json_cve_entry = '        \n' + json_cve_source + json_cve_id + json_cve_base_score +\
        json_cve_cvss_vector + json_module_name + json_version + json_vendor_url +\
        json_cve_description

    return json_cve_entry


class JsonReportVisitor(CveVisitor):
    """ This class implements a CVE visitor that produces a JSON report. The report
        is a single JSON file containing an array of all discovered CVEs. """

    def __init__(self):
        pass

    def start_visiting(self) -> str:
        return '{\n    \"cves\": [\n'

    def visit_source(self, cve_source: str, new_cves: List[Dict[str, str]],
                     old_cves: List[Dict[str, str]]) -> str:
        cve_json = ''

        for cve in new_cves + old_cves:
            cve_json += create_json_cve_entry(cve)
            cve_json += '             \"isNew\": ' + str(cve['is_new']).lower() + '\n        },\n'

        return cve_json

    def finished_visiting(self, dependencies: List[Dict[str, str]]) -> str:
        # End the CVE array with an empty element, then close the array, and finally
        # the top-level JSON structure
        return '        {\n        }\n    ]\n}'
