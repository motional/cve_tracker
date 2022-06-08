import unittest
from src.dependency_searchers.package_parsers import CsvParser


class TestCsvParser(unittest.TestCase):

    def test_parse_valid_file(self):
        cvs_data_valid = """modulename,version,latest,license
bitcoin,0.1,10.0,MIT
apache,1.0.1,1.0.2,MIT"""
    
        dependencies=CsvParser().parse(cvs_data_valid)

        self.assertEqual(len(dependencies), 2)

        self.assertEqual(dependencies[0]['ModuleName'], 'bitcoin')
        self.assertEqual(dependencies[0]['Version'], '0.1')
        self.assertEqual(dependencies[0]['License'], 'MIT')

        self.assertEqual(dependencies[1]['ModuleName'], 'apache')
        self.assertEqual(dependencies[1]['Version'], '1.0.1')
        self.assertEqual(dependencies[1]['License'], 'MIT')
        
    def test_parse_missing_version_column(self):
        csv_data_missing_version_column = """modulename,version,latest,license
fake_dep1,2.687,what_license
fake_dep2,2.1.0,NASA"""

        dependencies=CsvParser().parse(csv_data_missing_version_column)
        
        self.assertEqual(len(dependencies), 0)
        
    def test_parse_unexpected_empty_line(self):
        csv_data_unexpected_empty_line = """modulename,version,latest,license
bitcoin,0.1,10.0,MIT
apache,1.0.1,1.0.2,MIT
        """ # the spaces before this end quote are intentional to cause an invalid row

        dependencies=CsvParser().parse(csv_data_unexpected_empty_line)
        
        self.assertEqual(len(dependencies), 2)
        
        self.assertEqual(dependencies[0]['ModuleName'], 'bitcoin')
        self.assertEqual(dependencies[0]['Version'], '0.1')
        self.assertEqual(dependencies[0]['License'], 'MIT')

        self.assertEqual(dependencies[1]['ModuleName'], 'apache')
        self.assertEqual(dependencies[1]['Version'], '1.0.1')
        self.assertEqual(dependencies[1]['License'], 'MIT')

    def test_parse_empty_module_column(self):
        csv_data_empty_module_column = """modulename,version,latest,license
bitcoin,0.1,10.0,MIT
,1.0.1,1.0.2,MIT
"""

        dependencies = CsvParser().parse(csv_data_empty_module_column)
        
        self.assertEqual(len(dependencies), 1)

        self.assertEqual(dependencies[0]['ModuleName'], 'bitcoin')
        self.assertEqual(dependencies[0]['Version'], '0.1')
        self.assertEqual(dependencies[0]['License'], 'MIT')
        
    def test_parse_empty_version_column(self):
        csv_data_empty_version_column = """modulename,version,latest,license
bitcoin,,10.0,MIT
apache,1.0.1,1.0.2,MIT
"""

        dependencies = CsvParser().parse(csv_data_empty_version_column)
        
        self.assertEqual(len(dependencies), 1)

        self.assertEqual(dependencies[0]['ModuleName'], 'apache')
        self.assertEqual(dependencies[0]['Version'], '1.0.1')
        self.assertEqual(dependencies[0]['License'], 'MIT')


if __name__ == '__main__':
    unittest.main()
