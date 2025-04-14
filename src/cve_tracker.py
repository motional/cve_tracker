"""
This is the primary module for CVE Tracker. It contains the main method and a class
used to search NIST's National Vulnerability Database (NVD) for CVEs based on
module (dependency) name.

To run CVE tracker, set your own configuration in config.py then execute:

python3 cve_tracker.py
"""

import logging
import os
import time
import json
from typing import List, Dict, Union
import packaging.version
import requests
from config.config import Config
from src.report_creators.report_creator import ReportCreator
from logging.handlers import RotatingFileHandler


PREVIOUS_CVES_FILE = os.path.abspath('./data/previous_cves.dat')
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


class NistCveSearcher():
    """ This class consumes a list of dependencies that were defined in
        package files found by dependency searchers and queries the NIST
        NVD API to determine what known vulnerabilities (CVEs) exist in each
        dependency. The CVEs are then filtered to remove those that are not
        relevant to the specific version of the dependency in use. CVEs are
        organized in a data structure that clusters CVEs by source and
        whether the CVE has been seen by previous runs of CVE tracker.
        In lists of CVEs, each CVE entry is a dictionary with the following
        keys:

        * MODULE_SOURCE - used to identify where the dependency was extracted from.
            Generally this is set to a broad value (e.g. package type) that will be
            used to organize dependencies in reports.

        * ModuleName - the name of the dependency.

        * Version - the version of the dependency. This is used later to narrow
            down which CVEs from NIST apply to the dependency, if any.

        * BaseScore - the vulnerability's CVSS2 base score.

        * CVSSVector - a text representation of this vulnerability's CVSS2 metrics.

        * Description - a brief description of vulnerability.

        * URL - a link to a third party website with more information about the vulnerability.

        * is_new - True if the CVE was not seen in previous executions of CVE tracker. """

    def __init__(self):
        self._previous_cves = set()

        if os.path.exists(PREVIOUS_CVES_FILE):
            self._previous_cves = set(line.strip() for line in open(PREVIOUS_CVES_FILE))

        self._previous_cves_file = open(PREVIOUS_CVES_FILE, 'w')

    @staticmethod
    def _query_nvd_for_module_cves(mod_name: str, nist_api_key: str) -> List:
        cves = []
        nvd_search_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch='

        try:
            if nist_api_key:
                search_result = requests.get(url = nvd_search_url + mod_name, headers={'apiKey': nist_api_key})
            else:
                search_result = requests.get(url = nvd_search_url + mod_name)

            if search_result.ok:
                result_json = search_result.json()
                if 'error' in result_json:
                    logging.error("The NIST API returned the following error message: %s",
                                  result_json['message'])
                elif result_json['vulnerabilities']:
                    for results in result_json['vulnerabilities']:
                        cves.append(results)
                    # Sleep to stay within NIST's rate limit for those with or without an API key
                    # For more information please visit: https://nvd.nist.gov/developers
                    if not Config.NIST_TOKEN:
                        time.sleep(1.6)
                    else:
                        time.sleep(0.6)

            else:
                logging.error("The NIST API returned the following error code: %d",
                              search_result.status_code)
            return cves

        except requests.exceptions.ConnectionError:
            logging.error("The NIST API is not responding. If there are CVEs for %s, "
                          "they will not appear in the report.", mod_name)
            return cves

    @staticmethod
    def _version_start_end_check(mod_version: str,
                                 nist_config: Dict[str, Union[bool, str, list]]) -> str:

        version = ''
        parsed_version = packaging.version.parse(mod_version)
        if 'versionStartIncluding' in nist_config and \
                'versionEndIncluding' in nist_config and \
                packaging.version.parse(nist_config['versionStartIncluding']) <= parsed_version <= \
                packaging.version.parse(nist_config['versionEndIncluding']):
            version = mod_version
        elif 'versionStartExcluding' in nist_config and \
                'versionEndExcluding' in nist_config and \
                packaging.version.parse(nist_config['versionStartExcluding']) < parsed_version < \
                packaging.version.parse(nist_config['versionEndExcluding']):
            version = mod_version
        elif 'versionStartIncluding' in nist_config and \
                'versionEndExcluding' in nist_config and \
                packaging.version.parse(nist_config['versionStartIncluding']) <= parsed_version < \
                packaging.version.parse(nist_config['versionEndExcluding']):
            version = mod_version
        elif 'versionStartExcluding' in nist_config and \
                'versionEndIncluding' in nist_config and \
                packaging.version.parse(nist_config['versionStartExcluding']) < parsed_version <= \
                packaging.version.parse(nist_config['versionEndIncluding']):
            version = mod_version
        elif 'versionStartIncluding' in nist_config and \
                'versionEndIncluding' not in nist_config \
                and 'versionEndExcluding' not in nist_config and \
                packaging.version.parse(nist_config['versionStartIncluding']) <= parsed_version:
            version = mod_version
        elif 'versionStartExcluding' in nist_config and 'versionEndIncluding' not in nist_config \
                and 'versionEndExcluding' not in nist_config and \
                packaging.version.parse(nist_config['versionStartExcluding']) <= parsed_version:
            version = mod_version
        elif 'versionStartIncluding' not in nist_config and \
                'versionStartExcluding' not in nist_config and \
                'versionEndIncluding' in nist_config and \
                parsed_version <= packaging.version.parse(nist_config['versionEndIncluding']):
            version = mod_version
        elif 'versionStartIncluding' not in nist_config and \
                'versionStartExcluding' not in nist_config and \
                'versionEndExcluding' in nist_config and \
                parsed_version < packaging.version.parse(nist_config['versionEndExcluding']):
            version = mod_version

        return version

    @staticmethod
    def _find_key_for_metric(dict: List, keys: List) -> str:
        for key in keys:
            if key in dict:
                return key
        raise Exception('No key found in metrics dictionary - %s, %s' % (str(keys), str(dict)))

    @staticmethod
    def _get_exploit_catalog():
        known_exploits = set()
        known_exploit_url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        known_exploit_data = requests.get(known_exploit_url)
        if known_exploit_data.status_code == 200:
            response = known_exploit_data.text
            data = json.loads(response)
            for d in data['vulnerabilities']:
                known_exploits.add(d['cveID'])
        else:
            logging.warning("The CISA known exploited vulnerabilities request returned status code: " +
                            str(known_exploit_data.status_code) +
                            " Please check the CISA URL and try again.")

        return known_exploits

    @staticmethod
    def _check_known_exploits(cve_id: str, exploit_catalog: set) -> str:
        is_exploit = 'No'
        if cve_id in exploit_catalog:
            is_exploit = 'Yes'
        return is_exploit

    def _make_cve_entry(self, source: str, module_name: str,
                        version_number: str, data: List, exploit_catalog: set) -> Dict[str, str]:

        cve_id = data['cve']['id']
        description = data['cve']['descriptions'][0]['value']
        url = data['cve']['references'][0]['url']
        metrics_dict = data['cve']['metrics']

        metric_key = self._find_key_for_metric(metrics_dict, ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'])
        cvss_vector= metrics_dict[metric_key][0]['cvssData']['vectorString']
        basescore = metrics_dict[metric_key][0]['cvssData']['baseScore']
        known_exploit = self._check_known_exploits(cve_id, exploit_catalog)

        is_new_cve = cve_id not in self._previous_cves

        cve = {'MODULE_SOURCE': source, 'ID': cve_id, 'ModuleName': module_name,
               'Version': version_number, 'BaseScore': str(basescore),
               'CVSSVector': cvss_vector, 'Description': description, 'URL': url,
               'KnownExploit': known_exploit, 'is_new': is_new_cve}
        return cve

    def cve_search(self, dependencies: List[Dict[str, str]],
                   nist_token: str) -> Dict[str, Dict[str, List[str]]]:
        relevant_cves = {}
        exploit_catalog = self._get_exploit_catalog()
        for dependency in dependencies:
            nist_cve_response = self._query_nvd_for_module_cves(dependency['ModuleName'], nist_token)

            for nist_cve_entry in nist_cve_response:
                if 'configurations' in nist_cve_entry['cve']:
                    configurations_path = nist_cve_entry['cve']['configurations'][0]['nodes'][0]
                    configurations = configurations_path['cpeMatch'][0]

                    cpe_uri = configurations['criteria']
                    item = str(cpe_uri).split(":")
                    version_name = item[4]
                    version_number = item[5]

                    if version_name != dependency['ModuleName'] or \
                        version_number not in ('*', dependency['Version']):
                        continue

                    if version_number == '*':
                        version_number = self._version_start_end_check(dependency['Version'],
                                                                     configurations)

                        if not version_number:
                            continue

                    cve = self._make_cve_entry(dependency['MODULE_SOURCE'],
                                             dependency['ModuleName'],
                                             version_number, nist_cve_entry, exploit_catalog)

                    if dependency['MODULE_SOURCE'] not in relevant_cves:
                        relevant_cves[dependency['MODULE_SOURCE']] = {'New': [], 'Old': []}

                    if cve['is_new']:
                        relevant_cves[dependency['MODULE_SOURCE']]['New'].append(cve)
                        self._previous_cves_file.write(cve['ID'] + '\n')
                    else:
                        relevant_cves[dependency['MODULE_SOURCE']]['Old'].append(cve)

        self._previous_cves_file.close()

        return relevant_cves


def main():
    dependencies = []
    if Config.LOGGING_QUIET:
        logging.basicConfig(handlers=[RotatingFileHandler(filename=Config.LOGGING_FILE_NAME,
                                                          mode='w', maxBytes=512_000, backupCount=4)],
                            format='%(asctime)s %(levelname)s %(message)s',
                            datefmt='%Y-%m-%dT%H:%M:%S')
    for searcher_config in Config.SEARCHER_CONFIGS:
        if "search_uri" not in searcher_config:
            logging.warning("The following search_uri configuration entry does "
                            "not specify a search_uri: %s", str(searcher_config))
            continue

        if "search_pattern" not in searcher_config:
            logging.warning("The following searcher configuration entry does "
                            "not specify a search_pattern: %s", str(searcher_config))
            continue

        if "search_relative_path" in searcher_config:
                dependencies.extend(
                    searcher_config["search_uri"].search(searcher_config["search_pattern"],
                                                         searcher_config['search_relative_path']))

    cves = NistCveSearcher().cve_search(dependencies, Config.NIST_TOKEN)

    if cves:
        report_creator = ReportCreator(Config.REPORT_FILE_NAME + Config.REPORT_EXTENSION,
                                       Config.REPORT_VISITOR, dependencies, Config.NOTIFIER)
        report_creator.create_report(cves)
