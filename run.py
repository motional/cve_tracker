import src.cve_tracker
from argparse import HelpFormatter
import textwrap
import argparse

version_major = 1
version_minor = 0
version_bug = 0
version = str(version_major) + '.' + str(version_minor) + '.' + str(version_bug)

NAME = 'cve_tracker'
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
program_description = f'''
       
       cve_tracker: '''+ version + '''

       Created by Garth Scheidemantel on January 1 2020
       Copyright 2020. All rights reserved.

       Licensed under Motional

       Distributed on an "AS IS" basis without warranties
       or conditions of any kind, either express or implied.

       USAGE:
       You must create a configuration file to capture what datastores to search for which file types, what type of report to generate, what type of notification to issue. After that simply run `./run.py` to automatically collect dependencies and generate a report of their CVEs.

       Exit status:
       0      Success
       1      Failure
       '''

class RawFormatter(HelpFormatter):
    def _fill_text(self, text, width, indent):
        return "\n".join([textwrap.fill(line, width) for line in textwrap.indent(textwrap.dedent(text), indent).splitlines()])


parser = argparse.ArgumentParser(description=program_description, formatter_class=RawFormatter)
parser.add_argument('-v', '--version', action='store_true', help="version")
args = parser.parse_args()

if args.version:
    print(NAME + ' ' + version)
    exit(EXIT_SUCCESS)




def main():
    pass


if __name__ == '__main__':
    src.cve_tracker.main()

