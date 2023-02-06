import unittest
from src.dependency_searchers.dependency_searchers import ArtifactorySearcher
from src.dependency_searchers.package_parsers import ArtifactoryParser


class TestArtifactorySearcher(unittest.TestCase):

    def test_artifactory_searcher_bad_token(self):

        artifactory_search_pattern = {"opencv": ArtifactoryParser()}
        dependencies = ArtifactorySearcher('user@company.com', 'token',
                                         'https://registry.npmjs.org/').search(
            artifactory_search_pattern, '')
        self.assertEqual(len(dependencies), 0)

    def test_artifactory_searcher_bad_url(self):

        artifactory_search_pattern = {"opencv": ArtifactoryParser()}
        dependencies = ArtifactorySearcher('user@company.com', 'token',
                                         'https://notarealregistry.org/').search(
            artifactory_search_pattern, '')
        self.assertEqual(len(dependencies), 0)

    def test_artifactory_valid_response(self):
        artifactory_search_pattern = {"opencv": ArtifactoryParser()}
        uri_data = 'https://website.com/artifactory/api/storage/cache/opencv-1.0.0-none-any.whl'
        dependencies = artifactory_search_pattern['opencv'].parse(str(uri_data))
        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0]['ModuleName'], 'opencv')
        self.assertEqual(dependencies[0]['Version'], '1.0.0')
        self.assertEqual(dependencies[0]['License'], 'BSD-3')
