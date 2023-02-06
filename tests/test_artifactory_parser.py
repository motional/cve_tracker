import unittest
from src.dependency_searchers.package_parsers import ArtifactoryParser


class TestArtifactoryParser(unittest.TestCase):

    def test_parse_valid_artifactory_response(self):
        package_contents="""
         {
          "repo" : "pip-remote-cache",
          "path" : "/the/path/to/pyopenssl-23.0.0-py3-none-any.whl",
          "created" : "",
          "createdBy" : "",
          "lastModified" : "2023",
          "checksums" : {
            "sha1" : "",
            "md5" : "",
            "sha256" : ""
          }

        }
        """
        dependencies=ArtifactoryParser().parse(package_contents)
        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0]['ModuleName'], 'pyopenssl')
        self.assertEqual(dependencies[0]['Version'], '23.0.0')
        self.assertEqual(dependencies[0]['License'], 'Apache-2.0 License')

    def test_parse_missing_artifactory_path(self):
        package_contents = """
         {
          "repo" : "pip-remote-cache",
          "path" : "",
          "created" : "",
          "createdBy" : "",
          "lastModified" : "2023",
          "checksums" : {
            "sha1" : "",
            "md5" : "",
            "sha256" : ""
          }

        }
        """
        dependencies=ArtifactoryParser().parse(package_contents)
        self.assertEqual(len(dependencies), 0)

    def test_parse_missing_artifactory_version_number(self):
        package_contents="""
         {
          "repo" : "sqlite",
          "path" : "/the/path/to/sqlite.nov_version_listed.tar",
          "created" : "",
          "createdBy" : "",
          "lastModified" : "2023",
          "checksums" : {
            "sha1" : "",
            "md5" : "",
            "sha256" : ""
          }

        }
        """
        dependencies=ArtifactoryParser().parse(package_contents)
        self.assertEqual(len(dependencies), 0)

    def test_parse_artifactory_no_license_found(self):
        package_contents="""
         {
          "repo" : "random_lib",
          "path" : "/the/path/to/random_lib-1.0.0.whl",
          "created" : "",
          "createdBy" : "",
          "lastModified" : "2023",
          "checksums" : {
            "sha1" : "",
            "md5" : "",
            "sha256" : ""
          }

        }
        """
        dependencies=ArtifactoryParser().parse(package_contents)
        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0]['ModuleName'], 'random_lib')
        self.assertEqual(dependencies[0]['Version'], '1.0.0')
        self.assertEqual(dependencies[0]['License'], 'N/A')