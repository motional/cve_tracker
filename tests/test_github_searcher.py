from typing import List
import unittest
from unittest.mock import patch
from requests.exceptions import ConnectionError
from github import Github, BadCredentialsException, UnknownObjectException
from src.dependency_searchers.dependency_searchers import GitHubRepoSearcher
from src.dependency_searchers.package_parsers import PipParser


class TestGitLabSearcher(unittest.TestCase):

    @patch('github.Github.get_repo')
    def test_github_searcher_bad_token(self, mock_get_repo_call):
        mock_get_repo_call.side_effect = BadCredentialsException(401, "",
                              {"message": "Bad credentials",
                              "documentation_url": "https://docs.github.com/rest"})
        pip_search_pattern = {"requirements.txt": PipParser()}
    
        dependencies = GitHubRepoSearcher("bad_token", 'proj/repo').search(pip_search_pattern)

        # When the token is wrong there should be no crash and we should
        # get an empty list back
        self.assertEqual(len(dependencies), 0)

    @patch('github.Github.get_repo')
    def test_github_searcher_repo_doesnt_exist(self, mock_get_repo_call):
        mock_get_repo_call.side_effect = UnknownObjectException(404, "",
                                                               {"message": "Not Found", 
                                                               "documentation_url": "https://docs.github.com/rest/reference/repos#get-a-repository"})
        pip_search_pattern = {"requirements.txt": PipParser()}

        dependencies = GitHubRepoSearcher("fake_token", 'proj/repo').search(pip_search_pattern)

        # When the repo doesn't exist there should be no crash and we should
        # get an empty list back
        self.assertEqual(len(dependencies), 0)

    @patch('tests.test_github_searcher.SimpleGithubRepo.get_contents')
    @patch('github.Github.get_repo')
    def test_github_searcher_search_path_doesnt_exist(self, mock_get_repo_call, mock_get_contents_call):
        mock_get_repo_call.return_value = SimpleGithubRepo()
        mock_get_contents_call.side_effect = UnknownObjectException(404, "",
                                                                   {"message": "Not Found", 
                                                                   "documentation_url": "https://docs.github.com/rest/reference/repos#get-repository-content"})
        pip_search_pattern = {"requirements.txt": PipParser()}

        dependencies = GitHubRepoSearcher("fake_token", 'proj/repo').search(pip_search_pattern, "doesnt_exist")

        # When the search path doesn't exist there should be no crash and we should
        # get an empty list back
        self.assertEqual(len(dependencies), 0)
        
    @patch('github.Github.get_repo')
    def test_integration_github_searcher_valid_pip_configuration(self, mock_get_repo_call):
        mock_get_repo_call.return_value = SimpleGithubRepo()
        pip_search_pattern = {"requirements.txt": PipParser()}

        dependencies = GitHubRepoSearcher("fake_token", 'proj/repo').search(pip_search_pattern)

        self.assertEqual(len(dependencies), 2)

        self.assertEqual(dependencies[0]['ModuleName'], 'requests')
        self.assertEqual(dependencies[0]['Version'], '2.26.0')
        self.assertEqual(dependencies[0]['License'], 'Unknown')
        
        self.assertEqual(dependencies[1]['ModuleName'], 'pygithub')
        self.assertEqual(dependencies[1]['Version'], '1.55')
        self.assertEqual(dependencies[1]['License'], 'Unknown')


class SimpleGithubContent():
    decoded_content = """requests==2.26.0
pygithub==1.55"""
    path = '/some/fake/path/requirements.txt'
    type = 'file'


class SimpleGithubRepo():
    def get_contents(self, path: str) -> List[SimpleGithubContent]:
        return [SimpleGithubContent()]


if __name__ == '__main__':
    unittest.main()
