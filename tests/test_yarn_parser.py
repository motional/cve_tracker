import unittest
from src.dependency_searchers.package_parsers import YarnParser

class TestYarnParser(unittest.TestCase):

    def test_parse_valid_yarn_file(self):
        package_contents = """"@adobe/code-frame@^7.10.4":
  version "7.10.4"
  resolved "https://registry.npmjs.org/"
  integrity sha512-+uad9NC
"""
        dependencies = YarnParser().parse(package_contents)
        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0]['ModuleName'], 'code_frame')
        self.assertEqual(dependencies[0]['Version'], '7.10.4')
        self.assertEqual(dependencies[0]['License'], 'MIT')

    def test_invalid_yarn_file(self):
        package_contents = ''
        dependencies = YarnParser().parse(package_contents)
        self.assertEqual(len(dependencies), 0)


    def test_yarn_file_with_no_license_data(self):
        package_contents = """"@adobe/css-tools@^4.0.1":
  version "4.0.1"
  resolved "https://registry.npmjs.org/"
  integrity sha512-+uad9NC
"""
        dependencies = YarnParser().parse(package_contents)
        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0]['ModuleName'], 'css_tools')
        self.assertEqual(dependencies[0]['Version'], '4.0.1')
        self.assertEqual(dependencies[0]['License'], 'N/A')
