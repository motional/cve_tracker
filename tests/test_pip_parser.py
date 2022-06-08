import unittest
from src.dependency_searchers.package_parsers import PipParser


class TestPipParser(unittest.TestCase):

    def test_parse_valid_pip_file(self):
        pip_data_valid_set = b'boto3==1.9.91\nrequests==2.20.0\nrequests-aws4auth==0.9\n'

        dependencies = PipParser().parse(pip_data_valid_set)

        self.assertEqual(len(dependencies), 3)

        self.assertEqual(dependencies[0]['ModuleName'], 'boto3')
        self.assertEqual(dependencies[0]['Version'], '1.9.91')
        self.assertEqual(dependencies[0]['License'], 'Unknown')

        self.assertEqual(dependencies[1]['ModuleName'], 'requests')
        self.assertEqual(dependencies[1]['Version'], '2.20.0')
        self.assertEqual(dependencies[1]['License'], 'Unknown')

        self.assertEqual(dependencies[2]['ModuleName'], 'requests-aws4auth')
        self.assertEqual(dependencies[2]['Version'], '0.9')
        self.assertEqual(dependencies[2]['License'], 'Unknown')

    def test_parse_invalid_pip_file_missing_equality_operator(self):
        pip_data_invalid_set = b'boto3\n1.9.91\nrequests\n2.20.0\nrequests-aws4auth\n0.9\n'

        dependencies = PipParser().parse(pip_data_invalid_set)

        self.assertEqual(len(dependencies), 0)

    def test_partial_working_dependencies_missing_equality_operator_one_entry(self):
        pip_data_set_with_errors = b'boto3==1.9.91\nrequests==2.20.0\nrequests-aws4auth\n0.9\n'

        dependencies = PipParser().parse(pip_data_set_with_errors)

        self.assertEqual(len(dependencies), 2)

        self.assertEqual(dependencies[0]['ModuleName'], 'boto3')
        self.assertEqual(dependencies[0]['Version'], '1.9.91')
        self.assertEqual(dependencies[0]['License'], 'Unknown')

        self.assertEqual(dependencies[1]['ModuleName'], 'requests')
        self.assertEqual(dependencies[1]['Version'], '2.20.0')
        self.assertEqual(dependencies[1]['License'], 'Unknown')


if __name__ == '__main__':
    unittest.main()
