"""
This module provides parsers that take the contents of package files found by a
dependency searcher and extract the dependencies defined inside. Parsers are
provided to extract dependencies from the contents of the following package types:

- Bazel
- CSV (custom to this tool)
- Conan
- NPM
- PIP
- MAKE
- Yarn
"""

from abc import abstractmethod, ABCMeta
from io import StringIO
import csv
import logging
from typing import List, Dict
import re
import json
import requests
from bs4 import BeautifulSoup
import os
from pyarn import lockfile

# The URL of the NPM repository to use to fetch license data for dependencies.
NPM_URL = 'https://www.npmjs.com/package/'


def _find_license(version_name) -> str:
    current_dir = os.path.dirname(os.path.realpath(__file__))
    filename = os.path.join(current_dir, "licenses.csv")
    with open(filename, 'r') as license_dict:
        for rows in csv.DictReader(license_dict):
            if rows['Module_Name'] == version_name and 'License' in rows:
                return rows['License']
    return 'N/A'

class PackageParser(metaclass=ABCMeta):
    """ Abstract base class for parser classes that extract dependencies from
        the contents of package files. """

    @abstractmethod
    def parse(self, package_contents: str) -> List[Dict[str, str]]:
        """
        Parse the contents of a package to extract and return a list of
        the dependencies it defines. Each list entry is dictionary with
        the following keys:

        * MODULE_SOURCE - used to identify where the dependency was extracted from.
            Generally this is set to a broad value (e.g. package type) that will be
            used to organize dependencies in reports.

        * ModuleName - the name of the dependency, which will be used later in
            a query to the NIST API to search for CVEs.

        * Version - the version of the dependency. This is used later to narrow
            down which CVEs from NIST apply to the dependency, if any.

        * License - the license assigned to the dependency, if available. In some
            cases, like Bazel, there is not a means provided to define a dependency's
            license.

        Args:
            package_contents (str): a string containing the contents of a package
                file. It is the caller's responsibility to ensure this data is
                in a form that is suitable for parsing -- a UTF-8 string.

        Returns:
            list: a list of dictionaries, where each dictionary contains dependency
                metadata extracted from the package_contents
        """
        raise NotImplementedError("You did not implement the parse method")


class BazelParser(PackageParser):
    """ This class extracts dependencies defined in bazel (*.bzl) dependency files.
        Bazel is a build system open sourced by Google. Bazel does not provide a
        means to supply license information when defining a dependency. Thus,
        you can map known dependencies to their licenses in licenses.csv in this
        directory if you want this data available in reports. """



    def parse(self, package_contents: str) -> List[Dict[str, str]]:
        dependencies = []

        name_pattern = re.compile(r'\s*name\s*=\s*(?:\"|\')(.*)(?:\"|\')')
        name = ''
        version = ''

        for line in package_contents.split('\n'):
            match = name_pattern.match(line)
            if match:
                name = match.group(1)
                continue

            if name:
                version_pattern = re.compile(
                    r'\s*http.*' + name + r'-([a-zA-Z0-9-\.]*)\.tar|' + \
                    r'\s*http.*' + name + r'-([a-zA-Z0-9-\.]*)\.')

                match = version_pattern.search(line)

                if match:
                    version_match = match.group(1) if match.group(1) else match.group(2)

                    # some version numbers have a 'v' before the version number and some version numbers
                    # have a '-latest' at the end, we need to remove this to accurately match the version
                    # with the nist version
                    version_match = version_match.split('-')
                    version = version_match[0].strip('v')

            if name and version:
                dependency_license = _find_license(name)
                dependency = {'MODULE_SOURCE': str('Bazel Dependencies'), 'ModuleName': name,
                              'Version': version, 'License': dependency_license}
                dependencies.append(dependency)
                break

        return dependencies


class CsvParser(PackageParser):
    """ This class extracts dependencies defined in CSV (.csv) files custom to this tool.
        These CSV files are expected to have the following header:

        modulename,version,latest,license

        This tool supports CSV files like this to allow you to easily track CVEs assigned to
        software that is not managed by a supported package format. For example, if you use
        infrastructure software such as Jenkins or Artifactory, using a CSV file is
        an easy way to find about new CVEs in the versions you're using. """

    def parse(self, package_contents: str) -> List[Dict[str, str]]:
        dependencies = []

        reader = csv.reader(StringIO(package_contents))

        headers = []
        if reader:
            headers = next(reader, None)

        for row in reader:
            row = dict(zip(headers, row))

            if len(row) < len(headers):
                logging.warning("Skipping the following row because its number of columns "
                                "does not match the number of columns in the CSV header: \n{}"
                                .format(row))
                continue

            if not row['modulename']:
                logging.warning("Skipping the following row because its modulename column is "
                                "empty, which makes precise CVE matches impossible: \n{}"
                                .format(row))
                continue

            if not row['version']:
                logging.warning("Skipping the following row because its version column is "
                                "empty, which makes precise CVE matches impossible: \n{}"
                                .format(row))
                continue

            dependency = {'MODULE_SOURCE': 'Local Source Dependencies', 'ModuleName': row['modulename'],
                          'Version': row['version'], 'License': row['license']}
            logging.debug('Prepared new CSV dependency: %s', str(dependency))
            dependencies.append(dependency)

        return dependencies


class ConanParser(PackageParser):
    """ This class extracts dependencies defined in conan (conan.py) package files.
        Conan is an open source package manager for C/C++. """

    def parse(self, package_contents: str) -> List[Dict[str, str]]:
        # There will only be one dependency from a conanfile since each conanfile
        # belongs to only one dependency

        name_pattern = re.compile(r'\s*name\s*=\s*(?:\"|\')(.*)(?:\"|\')')
        version_pattern = re.compile(r'\s*version\s*=\s*(?:\"|\')(.*)(?:\"|\')')
        license_pattern = re.compile(r'\s*license\s*=\s*(?:\"|\')(.*)(?:\"|\')')
        name = ''
        version = ''
        module_license = ''
        module_source = 'Conan Dependencies'
        for line in package_contents.split('\n'):
            match = name_pattern.match(line)
            if match:
                name = match.group(1)
                continue

            match = version_pattern.match(line)
            if match:
                version = match.group(1)
                continue

            match=license_pattern.match(line)
            if match:
                module_license = match.group(1)
                break

        dependency = {'MODULE_SOURCE': module_source, 'ModuleName': name, 'Version': version,
                      'License': module_license}
        logging.debug('Prepared new Conan dependency: %s', str(dependency))

        return [dependency]


class NpmParser(PackageParser):
    """ This class extracts dependencies defined in NPM (package.json) package files.
        NPM is a package manager for the JavaScript runtime environment Node.js. """

    @staticmethod
    def _decode_data(data: bytes) -> Dict:
        decoded = data.decode("utf-8")
        package_data = json.loads(decoded)

        if 'dependencies' in package_data:
            return package_data['dependencies']
        if 'devDependencies' in package_data:
            return package_data['devDependencies']

        return {}

    def parse(self, package_contents: str) -> List[Dict[str, str]]:
        dependencies = []
        module_source = 'NPM Dependencies'
        package_data = self._decode_data(bytes(package_contents))
        if package_data:
            for item in package_data.items():
                module_name = item[0]
                version_number = item[1].strip('^')

                source = requests.get(NPM_URL + module_name).text
                soup = BeautifulSoup(source, 'html.parser')
                license_title_tag = soup.find("h3", text="License")
                license_name_tag = None

                if license_title_tag:
                    license_name_tag = license_title_tag.next_sibling

                if license_name_tag:
                    module_license = license_name_tag.text
                    dependencies.append({'MODULE_SOURCE': module_source, 'ModuleName': module_name,
                                         'Version': version_number,
                                         'License': module_license})
                else:
                    logging.warning("Could not find license for NPM module %s. "
                                    "Defaulting to 'unknown'.", module_name)
                    dependencies.append({'MODULE_SOURCE': module_source, 'ModuleName': module_name,
                                         'Version': version_number,
                                         'License': 'unknown'})

        return dependencies


class PipParser(PackageParser):
    """ This class extracts dependencies defined in pip (requirements.txt) package files.
        pip is a package manager commonly used for Python. """

    def parse(self, package_contents: str) -> List[Dict[str, str]]:
        black_list = ['motional-log']
        dependencies = []

        for row in package_contents.splitlines():
            dependency = str(row).replace('==', ',').replace("b'", '') \
                                 .strip('[]').replace("'", '').split(',')
            if len(dependency) > 1:
                module_name = dependency[0]
                if module_name in black_list:
                    break

                dependencies.append({'MODULE_SOURCE': 'Pip Dependencies', 'ModuleName': module_name,
                                     'Version': dependency[1],
                                     'License': 'Unknown'})

        return dependencies


class JsonParser(PackageParser):
    """ This class extracts dependencies defined in sources.json file custom to this tool.
            The sources.json files are expected to have the following:

            "ModuleName": "",
             "Version": "",
             "Latest": "",
             "License": ""

            This tool supports JSON files like this to allow you to easily track CVEs assigned to
            software that is not managed by a supported package format. For example, if you use
            infrastructure software such as Jenkins or Artifactory, using a JSON file is
            an easy way to find about new CVEs in the versions you're using. """

    def parse(self, package_contents: str) -> List[Dict[str, str]]:
        dependencies = []

        cve_dict = json.loads(package_contents)
        for item in cve_dict['sources']:
            if not item['ModuleName']:
                logging.warning("Skipping the following entry because its ModuleName column is "
                                "empty, which makes precise CVE matches impossible: \n")
            elif not item['Version']:
                logging.warning("Skipping the following entry because its Version column is "
                                "empty, which makes precise CVE matches impossible: \n")
            else:
                dependency = {'MODULE_SOURCE': 'Local Source Dependencies', 'ModuleName': item['ModuleName'],
                        'Version': item['Version'], 'License': item['License']}
                dependencies.append(dependency)
        return dependencies

class MakeFileParser(PackageParser):
    """ This class extracts dependencies defined in Make (*.mk) package files. .mk files used by
        software compilers and linkers for building program executable from source files. """

    def parse(self, package_contents: str) -> List[Dict[str, str]]:
        dependencies = []
        module_source = 'MakeFile Dependencies'
        module_name = ''
        version_number = ''
        module_license = ''
        contents = package_contents.replace('\\\n', '').strip().split('\n')
        dependency_pattern = re.compile('^\s*(\w+)_([a-zA-Z0-9]+)\s*(?:=|\\+=)\s*(\S|\S.*\S)\s*$', re.M)
        if contents:
            for line in contents:
                match = dependency_pattern.search(line)
                if match:
                    source_name, key, value = match.groups()
                    if 'VERSION' in key:
                        module_name = source_name.lower()
                        version_number = value
                    if 'LICENSE' in key:
                        module_license = value
            if version_number and not module_license:
                module_license = 'N/A'
            if not version_number:
                logging.warning("Skipping the following entry because the parser cannot locate a version number, "
                                "which makes precise CVE matches impossible: \n")
            else:
                dependencies.append({'MODULE_SOURCE': module_source, 'ModuleName': module_name,
                                     'Version': version_number,
                                     'License': module_license})
        return dependencies


class YarnParser(PackageParser):
    """ This class extracts dependencies defined in Yarn.lock (yarn.lock) package files."""
    @staticmethod
    def yarn_license_finder(module_name: str) -> str:
        source = requests.get(NPM_URL + module_name).text
        soup = BeautifulSoup(source, 'html.parser')
        license_title_tag = soup.find("h3", text="License")
        license_name_tag = None

        if license_title_tag:
            license_name_tag = license_title_tag.next_sibling

        if license_name_tag:
            module_license = license_name_tag.text

        else:
            logging.warning("Could not find license for Yarn dependency %s. "
                            "Defaulting to 'N/A'.", module_name)
            module_license = 'N/A'
        return module_license

    def parse(self, package_contents: str) -> List[Dict[str, str]]:
        dependencies = []
        module_source = 'Yarn Dependencies'
        dependency_pattern = re.compile('@(\w+)/(\w+(?:-\w+)*)(\D+)(\d+.\d+.\d+)')
        try:
            yarn_file = lockfile.Lockfile.from_str(package_contents)
            for data in yarn_file.data:
                modules = data.split(', ')
                for mod in modules:
                    match = dependency_pattern.match(mod)
                    if match:
                        module_name = match.group(2).replace('-', '_')
                        version_number = match.group(4)
                        if not version_number:
                            logging.warning("Skipping the following entry because the parser cannot locate a version number, "
                                "which makes precise CVE matches impossible: \n")

                        else:
                            module_license = self.yarn_license_finder(match.group(2))
                            dependencies.append({'MODULE_SOURCE': module_source, 'ModuleName': module_name,
                                                 'Version': version_number,
                                                 'License': module_license})

        except ValueError:
            logging.warning("Skipping the following file because the parser cannot locate the dependency data, "
                            "which makes precise CVE matches impossible: \n")

        return dependencies


class ArtifactoryParser(PackageParser):
    """ This class extracts dependencies found in only in the Jfrog Artifactory datastore.
    Note: This parser will not work with any other package parser."""
    def parse(self, package_contents: str) -> List[Dict[str, str]]:
        dependencies = []
        module_source = 'Artifactory Dependencies'
        dependency_pattern = re.compile(r'(\w*)-(\d+.\d+.\d+)')
        for contents in package_contents.split(','):
            match = dependency_pattern.search(contents)
            if match:
                module_name = match.group(1)
                version_number = match.group(2)
                if version_number:
                    module_license=_find_license(module_name)
                    dependency={'MODULE_SOURCE': module_source, 'ModuleName': module_name, 'Version': version_number,
                                'License': module_license}
                    dependencies.append(dependency)
                else:
                    logging.warning("Skipping the following entry because its Version column is "
                                    "empty, which makes precise CVE matches impossible: \n")

        return dependencies
