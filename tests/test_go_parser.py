import unittest
from src.dependency_searchers.package_parsers import GoParser


class TestGoParser(unittest.TestCase):

    def test_go_parser_with_valid_file(self):
        package_contents = """module go_module/for/this/example

        go 1.0


        require (
        	github.com/golang/protobuf v1.5.3 // indirect
        	google.golang.org/protobuf v1.30.0 // indirect
        """

        dependencies = GoParser().parse(package_contents)
        self.assertEqual(len(dependencies), 2)

        self.assertEqual(dependencies[0]['ModuleName'], 'protobuf')
        self.assertEqual(dependencies[0]['Version'], '1.5.3')
        self.assertEqual(dependencies[0]['License'], 'BSD-3-Clause')

        self.assertEqual(dependencies[1]['ModuleName'], 'protobuf')
        self.assertEqual(dependencies[1]['Version'], '1.30.0')
        self.assertEqual(dependencies[1]['License'], 'BSD-3-Clause')

    def test_go_parser_with_invalid_file(self):
        package_contents = """module go_module/for/this/example

go 1.0

require (
	google.golang.org/MISSING Dependencies 
)

"""

        dependencies = GoParser().parse(package_contents)

        self.assertEqual(len(dependencies), 0)

    def test_go_parser_with_no_license(self):
        package_contents = """module go_module/in/this/location

        go 1.0


        require (
        	golang.org/x/net v0.1.1 // indirect
        """
        dependencies = GoParser().parse(package_contents)

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0]['ModuleName'], 'net')
        self.assertEqual(dependencies[0]['Version'], '0.1.1')
        self.assertEqual(dependencies[0]['License'], 'N/A')

