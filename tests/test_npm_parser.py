import unittest
from unittest.mock import patch
from src.dependency_searchers.package_parsers import NpmParser


class TestNpmParser(unittest.TestCase):

    @patch('requests.get')
    def test_parse_valid_file(self, mock_get_call):
        mock_get_call.return_value = MitLicenseResponse()
        npm_data = b'{\n"dependencies": {\n    "@fortawesome/fontawesome-svg-core": "^1.2.36",\n    "@fortawesome/free-solid-svg-icons": "^5.15.4"\n  },\n  "devDependencies": {\n    "@babel/core": "^7.15.8"\n }\n}\n'

        test_data = NpmParser().parse(npm_data)

        self.assertEqual(len(test_data), 2)
        self.assertEqual(test_data[0]['ModuleName'], '@fortawesome/fontawesome-svg-core')
        self.assertEqual(test_data[0]['Version'], '1.2.36')
        self.assertEqual(test_data[0]['License'], 'MIT')

        # The real license for this is (CC-BY-4.0 AND MIT) in practice, but since
        # we're mocking the HTTP request that gets the real license information, every
        # license in this test will be MIT
        self.assertEqual(test_data[1]['ModuleName'], '@fortawesome/free-solid-svg-icons')
        self.assertEqual(test_data[1]['Version'], '5.15.4')
        self.assertEqual(test_data[1]['License'], 'MIT')

    def test_invalid_file_bad_keys(self):
        npm_data = b'{\n"dev": {\n    "jedkhs": "^1.2.36",\n    "free_icons": "^5.15.4"\n  },\n  "source": {\n    "ore": "^7.15.8"\n }\n}\n'

        test_data = NpmParser().parse(npm_data)

        self.assertEqual(len(test_data), 0)

    @patch('requests.get')
    def test_parse_dependencies_unknown_licenses(self, mock_get_call):
        mock_get_call.return_value = UnknownLicenseResponse()
        npm_data = b'{\n"dependencies": {\n    "jedkhs": "^1.2.36",\n    "free_icons": "^5.15.4"\n  },\n  "devDependencies": {\n    "ore": "^7.15.8"\n }\n}\n'

        test_data = NpmParser().parse(npm_data)
        self.assertEqual(len(test_data), 2)

        self.assertEqual(test_data[0]['ModuleName'], 'jedkhs')
        self.assertEqual(test_data[0]['Version'], '1.2.36')
        self.assertEqual(test_data[0]['License'], 'unknown')

        self.assertEqual(test_data[1]['ModuleName'], 'free_icons')
        self.assertEqual(test_data[1]['Version'], '5.15.4')
        self.assertEqual(test_data[1]['License'], 'unknown')

    @patch('requests.get')
    def test_partial_working_dependencies(self, mock_get_call):
        mock_get_call.return_value = MitLicenseResponse()
        npm_data = b'{\n"dependencies": {\n    "humps": "^2.0.1",\n    "react-ga": "^3.3.0"\n  },\n  "devDependencies": {\n     "ore": "^7.15.8"\n }\n}\n'

        test_data = NpmParser().parse(npm_data)

        self.assertEqual(len(test_data), 2)

        self.assertEqual(test_data[0]['ModuleName'], 'humps')
        self.assertEqual(test_data[0]['Version'], '2.0.1')
        self.assertEqual(test_data[0]['License'], 'MIT')

        self.assertEqual(test_data[1]['ModuleName'], 'react-ga')
        self.assertEqual(test_data[1]['Version'], '3.3.0')
        self.assertEqual(test_data[1]['License'], 'MIT')

    @patch('requests.get')
    def test_version_number_sanitizer_remove_carrot_from_version(self, mock_get_call):
        mock_get_call.return_value = MitLicenseResponse()
        npm_data = b'{\n"dependencies": {\n    "@fortawesome/fontawesome-svg-core": "^1.2.36",\n    "@fortawesome/free-solid-svg-icons": "^5.15.4"\n  },\n  "devDependencies": {\n    "@babel/core": "^7.15.8"\n }\n}\n'

        test_data = NpmParser().parse(npm_data)

        self.assertEqual(len(test_data), 2)
        self.assertEqual(test_data[0]['Version'], '1.2.36')
        self.assertEqual(test_data[1]['Version'], '5.15.4')


class UnknownLicenseResponse():
    text = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">    
  </head>
  <body>
  </body>
</html>"""


class MitLicenseResponse():
    text = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">    
  </head>
  <body>
<title>Downloads</title><g><polygon points="4.59 4.94 4.59 0 2.62 0 2.62 4.94 0 4.94 3.28 9.53 7.22 4.94 4.59 4.94"></polygon><rect x="0.11" y="10.76" width="7" height="1"></rect></g></svg>Weekly Downloads</h3><div class="_000ae427 flex flex-row-reverse items-end"><svg class="_418c4939 flex-none" width="200" height="40" stroke-width="3" stroke="#8956FF" fill="rgba(137, 86, 255, .2)"></svg><p class="_9ba9a726 f4 tl flex-auto fw6 black-80 ma0 pr2 pb1">580,103</p></div></div></div><div class="_702d723c dib w-50 bb b--black-10 pr2"><h3 class="c84e15be f5 mt2 pt2 mb0">Version</h3><p class="f2874b88 fw6 mb3 mt2 truncate black-80 f4">2.0.1</p></div><div class="_702d723c dib w-50 bb b--black-10 pr2"><h3 class="c84e15be f5 mt2 pt2 mb0">License</h3><p class="f2874b88 fw6 mb3 mt2 truncate black-80 f4">MIT</p></div><div class="_702d723c dib w-50 bb b--black-10 pr2 w-100"><h3 class="c84e15be f5 mt2 pt2 mb0">Last publish</h3><p class="f2874b88 fw6 mb3 mt2 truncate black-80 f4"><time dateTime="2017-06-18T13:20:01.764Z" title="6/18/2017, 1:20:01 PM">5 years ago</time></p></div>
  </body>
</html>"""


if __name__ == '__main__':
    unittest.main()
