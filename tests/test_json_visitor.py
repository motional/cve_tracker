import json
import unittest
from src.report_creators.json_report_visitor import JsonReportVisitor
from src.report_creators.json_report_visitor import create_json_cve_entry

class TestJsonVisitor(unittest.TestCase):

    def test_valid_cve_entry_to_json(self):
        cve = {'MODULE_SOURCE': 'Pip Dependencies', 'ID': 'CVE_2021_123', 'ModuleName': 'boto3',
               'Version': '1.9.91', 'BaseScore': '9.0',
               'CVSSVector': 'cvss_vector_here', 'Description': 'A fake vulnerability.',
               'URL': 'http://example.com', 'KnownExploit': 'No', 'is_new': True}

        json_string = create_json_cve_entry(cve)
        json_string += '             \"isNew\": ' + str(cve['is_new']).lower() + '\n        }\n'

        # This will throw an exception and cause the test to fail if the json is invalid
        parsed_json = json.loads(json_string)

        self.assertEqual(parsed_json['KnownExploit'], 'No')
        self.assertEqual(parsed_json['ID'], 'CVE_2021_123')
        self.assertEqual(parsed_json['ModuleName'], 'boto3')
        self.assertEqual(parsed_json['Version'], '1.9.91')
        self.assertEqual(parsed_json['BaseScore'], '9.0')
        self.assertEqual(parsed_json['CVSSVector'], 'cvss_vector_here')
        self.assertEqual(parsed_json['Description'], 'A fake vulnerability.')
        self.assertEqual(parsed_json['URL'], 'http://example.com')
        self.assertEqual(parsed_json['isNew'], True)

    def test_full_basic_report(self):
        json_visitor = JsonReportVisitor()

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

        json_string = json_visitor.start_visiting()
        json_string += json_visitor.visit_source('Pip Dependencies', [new_cve], [old_cve])
        json_string += json_visitor.finished_visiting([dependency])

        # This will throw an exception and cause the test to fail if the json is invalid
        parsed_json = json.loads(json_string)

        self.assertEqual(parsed_json['cves'][0]['KnownExploit'], 'No')
        self.assertEqual(parsed_json['cves'][0]['ID'], 'CVE_2021_123')
        self.assertEqual(parsed_json['cves'][0]['ModuleName'], 'boto3')
        self.assertEqual(parsed_json['cves'][0]['Version'], '1.9.91')
        self.assertEqual(parsed_json['cves'][0]['BaseScore'], '9.0')
        self.assertEqual(parsed_json['cves'][0]['CVSSVector'], 'cvss_vector_here')
        self.assertEqual(parsed_json['cves'][0]['Description'], 'A fake vulnerability.')
        self.assertEqual(parsed_json['cves'][0]['URL'], 'http://example.com')
        self.assertEqual(parsed_json['cves'][0]['isNew'], True)

        self.assertEqual(parsed_json['cves'][1]['KnownExploit'], 'No')
        self.assertEqual(parsed_json['cves'][1]['ID'], 'CVE_2021_456')
        self.assertEqual(parsed_json['cves'][1]['ModuleName'], 'boto3')
        self.assertEqual(parsed_json['cves'][1]['Version'], '1.9.91')
        self.assertEqual(parsed_json['cves'][1]['BaseScore'], '8.0')
        self.assertEqual(parsed_json['cves'][1]['CVSSVector'], 'another_cvss_vector_here')
        self.assertEqual(parsed_json['cves'][1]['Description'], 'Another fake vulnerability.')
        self.assertEqual(parsed_json['cves'][1]['URL'], 'http://example.com')
        self.assertEqual(parsed_json['cves'][1]['isNew'], False)


if __name__ == '__main__':
    unittest.main()
