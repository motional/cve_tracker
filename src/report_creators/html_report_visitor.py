from typing import List, Dict
from src.report_creators.cve_visitor import CveVisitor

HTML_INTRO = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CVE Tracker Report</title>
<style>
body {font-family: Arial;}

/* Style the tab */
.tab {
  overflow: hidden;
  border: 1px solid #ccc;
  background-color: MediumSlateBlue;
}

/* Style the buttons inside the tab */
.tab button {
  background-color: inherit;
  float: left;
  border: none;
  outline: none;
  cursor: pointer;
  padding: 14px 16px;
  transition: 0.3s;
  font-size: 17px;
}

/* Change background color of buttons on hover */
.tab button:hover {
  background-color: #ddd;
}

/* Create an active/current tablink class */
.tab button.active {
  background-color: #ccc;
}

/* Style the tab content */
.tabcontent {
  display: none;
  padding: 6px 12px;
  border: 1px solid #ccc;
  border-top: none;
}

table.darkTable {
  font-family: "Arial Black", Gadget, sans-serif;
  border: 2px solid #000000;
  background-color: #0C090A;
  width: 90%;
  height: 200px;
  margin-bottom: 15px;
  text-align: left;
  border-collapse: collapse;
}

table.darkTable td, table.darkTable th {
  border: 1px solid #4A4A4A;
  padding: 9px 8px;
}

table.darkTable tbody td {
  font-size: 13px;
  color: #FFFFFF;
}

table.darkTable tr:nth-child(even) {
  background: #888888;
}

table.darkTable thead {
  background: #7B68EE;
  border-bottom: 3px solid #000000;
}

table.darkTable thead th {
  font-size: 15px;
  font-weight: bold;
  color: #000000;
  text-align: center;
  border-left: 2px solid #4A4A4A;
}

table.darkTable thead th:first-child {
  border-left: none;
}

table.darkTable tfoot {
  font-size: 12px;
  font-weight: bold;
  color: #E6E6E6;
  background: #000000;
  background: -moz-linear-gradient(top, #404040 0%, #191919 66%, #000000 75%);
  background: -webkit-linear-gradient(top, #404040 0%, #191919 66%, #000000 75%);
  background: linear-gradient(to bottom, #404040 0%, #191919 66%, #000000 75%);
  border-top: 1px solid #4A4A4A;
}

table.darkTable tfoot td {
  font-size: 12px;
}
</style>
</head>
<body style="background-color: #E6E6E6">
<h2>Vulnerability Report</h2>
<p>Click on the buttons inside the tabbed menu:</p>

<div class="tab">
  <button class="tablinks" onclick="openPackageReport(event, 'Artifactory Dependencies')">Artifactory Dependencies</button>
  <button class="tablinks" onclick="openPackageReport(event, 'Bazel Dependencies')">Bazel Dependencies</button>
  <button class="tablinks" onclick="openPackageReport(event, 'Conan Dependencies')">Conan Dependencies</button>
  <button class="tablinks" onclick="openPackageReport(event, 'Pip Dependencies')">Pip Dependencies</button>
  <button class="tablinks" onclick="openPackageReport(event, 'NPM Dependencies')">NPM Dependencies</button>
  <button class="tablinks" onclick="openPackageReport(event, 'MakeFile Dependencies')">MakeFile Dependencies</button>
  <button class="tablinks" onclick="openPackageReport(event, 'Yarn Dependencies')">Yarn Dependencies</button>
  <button class="tablinks" onclick="openPackageReport(event, 'Local Source Dependencies')">Local Source Dependencies</button>
  <button class="tablinks" onclick="openPackageReport(event, 'license_data')">License Data</button>
</div>"""
HTML_TABLE_CVE = """
<table class="darkTable">
  <caption style="font-size: xx-large;">{} Vulnerabilities</caption>
  <thead>
    <tr>
      <th>Known Exploit</th>
      <th>CVE ID</th>
      <th>CVSS Base Score</th>
      <th>CVSS Vector</th>
      <th>Vendor Name</th>
      <th>Affected Version</th>
      <th>Vendor URL</th>
      <th>CVE Description</th>
    </tr>
  </thead>
  <tfoot>
    <tr>
      <th>Known Exploit</th>
      <th>CVE ID</th>
      <th>CVSS Base Score</th>
      <th>CVSS Vector</th>
      <th>Vendor Name</th>
      <th>Affected Version</th>
      <th>Vendor URL</th>
      <th>CVE Description</th>
    </tr>
  </tfoot>
  <tbody>
"""
LICENSE_HTML_TABLE_LOGIC = """
<div id="license_data" class="tabcontent">
"""
LICENSE_HTML_TABLE = """
<table class="darkTable">
<caption><font size="+3"> License Report </font> <br /> Licenses used: {} </caption>
  <caption><font size="+3">License Data</font></caption>
  <thead>
    <tr>
      <th>Vendor Name</th>
      <th>Version</th>
      <th>License</th>
    </tr>
  </thead>
  <tfoot>
    <tr>
      <th>Vendor Name</th>
      <th>Version</th>
      <th>License</th>
    </tr>
  </tfoot>
  <tbody>
"""

END_DIV = "</div>"
HTML_END_TABLE = """  </tbody>
</table>
</div>

"""
HTML_TABLE_BREAK = """
  </tbody>
</table>


"""
HTML_END = """
<script>
function openPackageReport(evt, cityName) {
  var i, tabcontent, tablinks;
  tabcontent = document.getElementsByClassName("tabcontent");
  for (i = 0; i < tabcontent.length; i++) {
    tabcontent[i].style.display = "none";
  }
  tablinks = document.getElementsByClassName("tablinks");
  for (i = 0; i < tablinks.length; i++) {
    tablinks[i].className = tablinks[i].className.replace(" active", "");
  }
  document.getElementById(cityName).style.display = "block";
  evt.currentTarget.className += " active";
}
</script>

<h1 style="color: Tomato">CONFIDENTIALITY NOTICE</h1>
<p>
Contains Confidential, Proprietary, or Privileged Information Exempt from Public Disclosure.
</p>

</body>
</html>"""


def create_html_cve_entry(cve: Dict[str, str]) -> str:
    html_known_exploit = '      <td>' + cve['KnownExploit'] + '</td>\n'
    html_cve_id = '      <td>' + cve['ID'] + '</td>\n'
    html_cve_basescore = '      <td>' + str(cve['BaseScore']) + '</td>\n'
    html_cve_attack_path = '      <td>' + cve['CVSSVector'] + '</td>\n'
    html_module_name = '      <td>' + cve['ModuleName'] + '</td>\n'
    html_affected_version = '      <td>' + str(cve['Version']) + '</td>\n'
    html_vendor_url = '      <td><a href=\"' + cve['URL'] + '\">' + cve['URL'] + '</a></td>\n'
    html_cve_description = '      <td>' + cve['Description'] + '</td>\n'
    html_cve_entry = '    <tr>\n' + html_known_exploit + html_cve_id + html_cve_basescore + \
        html_cve_attack_path + html_module_name + \
        html_affected_version + html_vendor_url + \
        html_cve_description + '    </tr>\n'
    return html_cve_entry


def create_html_license_entry(dependency: Dict[str, str]) -> str:
    html_module_name = '      <td>' + dependency['ModuleName'] + '</td>\n'
    html_version = '      <td>' + dependency['Version'] + '</td>\n'
    html_vendor_license = '      <td>' + dependency['License'] + '</td>\n'
    html_license_entry = '    <tr>\n' + html_module_name + html_version + \
        html_vendor_license + '    </tr>\n'
    return html_license_entry


class HtmlReportVisitor(CveVisitor):
    """ This class implements a CVE visitor that produces an HTML report. The report
        is a single HTML file containing all discovered CVEs. Findings are separated into
        tabs by the type of the package file that defined the vulnerable module. """

    def start_visiting(self) -> str:
        html = ''
        html += HTML_INTRO
        return html

    def visit_source(self, cve_source: str, new_cves: List[Dict[str, str]],
                     old_cves: List[Dict[str, str]]) -> str:
        html = ''
        div_start = '<div id="'
        div_end = '" class="tabcontent">'
        tag_id = cve_source
        html += div_start + tag_id + div_end
        if new_cves:
            html += HTML_TABLE_CVE.format("New")

        for new_cve in new_cves:
            html += create_html_cve_entry(new_cve)

        html += HTML_TABLE_BREAK

        if old_cves:
            html += HTML_TABLE_CVE.format("Known")

        for old_cve in old_cves:
            html += create_html_cve_entry(old_cve)

        html += HTML_TABLE_BREAK + END_DIV

        return html

    def finished_visiting(self, dependencies: List[Dict[str, str]]) -> str:
        licenses = set()
        license_table_body = ''

        for dependency in dependencies:
            licenses.update(dependency['License'].split(', '))
            license_table_body += create_html_license_entry(dependency)

        license_summary = list(licenses)
        license_summary.sort()
        license_summary_string = ', '.join(license_summary)

        final_html = LICENSE_HTML_TABLE_LOGIC + LICENSE_HTML_TABLE.format(license_summary_string) \
                   + license_table_body + HTML_END_TABLE + HTML_END

        return final_html
