import unittest
from src.dependency_searchers.package_parsers import JsonParser


class TestJsonParser(unittest.TestCase):
    def test_parse_valid_file(self):
        json_data_valid="""{
    "sources": [

        {
             "ModuleName": "bitcoin",
             "Version": "0.1",
             "Latest": "7.7.3",
             "License": "MIT"

        }
    ]
}"""

        dependencies=JsonParser().parse(json_data_valid)
        self.assertEqual(len(dependencies), 1)

        self.assertEqual(dependencies[0]['ModuleName'], 'bitcoin')
        self.assertEqual(dependencies[0]['Version'], '0.1')
        self.assertEqual(dependencies[0]['License'], 'MIT')

    def test_parse_missing_module_name(self):
        json_data_missing_module_name = """ {
        "sources": [

            {
                 "ModuleName": "",
                 "Version": "8.11.1",
                 "Latest": "8.11.1",
                 "License": "MIT"

            },
          {
                 "ModuleName": "jira",
                 "Version": "8.11.1",
                 "Latest": "8.11.1",
                 "License": "Proprietary"

            }
        ]
    }"""
        dependencies = JsonParser().parse(str(json_data_missing_module_name))
        self.assertEqual(len(dependencies), 1)

    def test_parse_missing_version(self):
        json_data_missing_version = """ {
    "sources": [

        {
             "ModuleName": "jenkins",
             "Version": "",
             "Latest": "8.11.1",
             "License": "MIT"

        },
      {
             "ModuleName": "jira",
             "Version": "8.11.1",
             "Latest": "8.11.1",
             "License": "Proprietary"

        }
    ]
}"""
        dependencies = JsonParser().parse(str(json_data_missing_version))
        self.assertEqual(len(dependencies), 1)
