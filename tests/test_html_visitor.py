import unittest
from bs4 import BeautifulSoup
from src.report_creators.html_report_visitor import HtmlReportVisitor
from src.report_creators.html_report_visitor import create_html_cve_entry

class TestHtmlVisitor(unittest.TestCase):

    def test_valid_cve_entry_to_html(self):
        cve = {'MODULE_SOURCE': 'Pip Dependencies', 'ID': 'CVE_2021_123', 'ModuleName': 'boto3',
               'Version': '1.9.91', 'BaseScore': '9.0',
               'CVSSVector': 'cvss_vector_here', 'Description': 'A fake vulnerability.',
               'URL': 'http://example.com', 'KnownExploit': 'No', 'is_new': True}

        html_string = create_html_cve_entry(cve)

        parsed_html = BeautifulSoup(html_string, "html.parser")
        td_tags = parsed_html.find_all('td')

        self.assertEqual(td_tags[0].text, 'No')
        self.assertEqual(td_tags[1].text, 'CVE_2021_123')
        self.assertEqual(td_tags[2].text, '9.0')
        self.assertEqual(td_tags[3].text, 'cvss_vector_here')
        self.assertEqual(td_tags[4].text, 'boto3')
        self.assertEqual(td_tags[5].text, '1.9.91')
        self.assertEqual(td_tags[6].text, 'http://example.com')
        self.assertEqual(td_tags[7].text, 'A fake vulnerability.')

    def test_full_basic_report(self):
        html_visitor = HtmlReportVisitor()

        dependency = {'MODULE_SOURCE': 'Pip Dependencies', 'ModuleName': 'boto3',
                      'Version': '1.9.91', 'License': 'Dunno'}

        new_cve = {'MODULE_SOURCE': 'Pip Dependencies', 'ID': 'CVE_2021_123', 'ModuleName': 'boto3',
                   'Version': '1.9.91', 'BaseScore': '9.0',
                   'CVSSVector': 'cvss_vector_here', 'Description': 'A fake vulnerability.',
                   'URL': 'http://example.com', 'KnownExploit': 'No', 'is_new': True}

        old_cve = {'MODULE_SOURCE': 'Pip Dependencies', 'ID': 'CVE_2021_456', 'ModuleName': 'boto3',
                   'Version': '1.9.91', 'BaseScore': '8.0',
                   'CVSSVector': 'another_cvss_vector_here', 'Description': 'Another fake vulnerability.',
                   'URL': 'http://example.com', 'KnownExploit': 'No', 'is_new': False}

        html_string = html_visitor.start_visiting()
        html_string += html_visitor.visit_source('Pip Dependencies', [new_cve], [old_cve])
        html_string += html_visitor.finished_visiting([dependency])

        parsed_html = BeautifulSoup(html_string, "html.parser")
        td_tags = parsed_html.find_all('td')

        self.assertEqual(td_tags[0].text, 'No')
        self.assertEqual(td_tags[1].text, 'CVE_2021_123')
        self.assertEqual(td_tags[2].text, '9.0')
        self.assertEqual(td_tags[3].text, 'cvss_vector_here')
        self.assertEqual(td_tags[4].text, 'boto3')
        self.assertEqual(td_tags[5].text, '1.9.91')
        self.assertEqual(td_tags[6].text, 'http://example.com')
        self.assertEqual(td_tags[7].text, 'A fake vulnerability.')

        self.assertEqual(td_tags[8].text, 'No')
        self.assertEqual(td_tags[9].text, 'CVE_2021_456')
        self.assertEqual(td_tags[10].text, '8.0')
        self.assertEqual(td_tags[11].text, 'another_cvss_vector_here')
        self.assertEqual(td_tags[12].text, 'boto3')
        self.assertEqual(td_tags[13].text, '1.9.91')
        self.assertEqual(td_tags[14].text, 'http://example.com')
        self.assertEqual(td_tags[15].text, 'Another fake vulnerability.')


if __name__ == '__main__':
    unittest.main()
