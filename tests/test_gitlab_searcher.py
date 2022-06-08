import base64
from typing import Any, Dict, List
import unittest
from unittest.mock import patch
from requests.exceptions import ConnectionError
import gitlab
from gitlab import GitlabAuthenticationError, GitlabParsingError
from src.dependency_searchers.dependency_searchers import GitLabRepoSearcher
from src.dependency_searchers.package_parsers import BazelParser, PipParser

class TestGitLabSearcher(unittest.TestCase):
    @patch('gitlab.Gitlab.auth')
    def test_gitlab_searcher_bad_token(self, mock_auth_call):
        mock_auth_call.side_effect = GitlabAuthenticationError()
        bazel_search_pattern = {'repo.bzl': BazelParser()}
    
        dependencies = GitLabRepoSearcher('token', 'https://gitlab.fake.example.com', 'proj/repo').search(bazel_search_pattern, 'folder/')

        # When the token is wrong there should be no crash and we should
        # get an empty list back
        self.assertEqual(len(dependencies), 0)


    @patch('gitlab.Gitlab.auth')
    def test_gitlab_searcher_bad_url(self, mock_auth_call):
        mock_auth_call.side_effect = ConnectionError()
        bazel_search_pattern = {'repo.bzl': BazelParser()}

        dependencies = GitLabRepoSearcher('token', 'https://gitlab.fake.example.com', 'proj/repo').search(bazel_search_pattern, 'folder/')

        # When the URL is wrong there should be no crash and we should
        # get an empty list back
        self.assertEqual(len(dependencies), 0)

    @patch('gitlab.Gitlab.auth')
    def test_gitlab_searcher_bad_project(self, mock_auth_call):
        mock_auth_call.side_effect = GitlabParsingError()
        bazel_search_pattern={'repo.bzl': BazelParser()}

        dependencies=GitLabRepoSearcher('token', 'https://gitlab.fake.example.com', 'bad/project').search(
            bazel_search_pattern, 'folder/')

        # When the project is wrong there should be no crash and we should
        # get an empty list back
        self.assertEqual(len(dependencies), 0)

    @patch('gitlab.Gitlab.auth')
    def test_gitlab_searcher_bad_search_path(self, mock_auth_call):
        mock_auth_call.side_effect = GitlabParsingError()
        bazel_search_pattern={'repo.bzl': BazelParser()}

        dependencies=GitLabRepoSearcher('token', 'https://gitlab.fake.example.com', 'proj/repo').search(
            bazel_search_pattern, 'bad/folder')

        # When the search path is wrong there should be no crash and we should
        # get an empty list back
        self.assertEqual(len(dependencies), 0)

    @patch('gitlab.Gitlab')
    def test_integration_gitlab_searcher_valid_pip_configuration(self, mock_init_call):
        mock_init_call.return_value = SimpleGitlab()
        pip_search_pattern = {"requirements.txt": PipParser()}

        dependencies = GitLabRepoSearcher('token', 'https://gitlab.fake.example.com', 'proj/repo').search(pip_search_pattern)

        self.assertEqual(len(dependencies), 2)

        self.assertEqual(dependencies[0]['ModuleName'], 'requests')
        self.assertEqual(dependencies[0]['Version'], '2.26.0')
        self.assertEqual(dependencies[0]['License'], 'Unknown')
        
        self.assertEqual(dependencies[1]['ModuleName'], 'pygithub')
        self.assertEqual(dependencies[1]['Version'], '1.55')
        self.assertEqual(dependencies[1]['License'], 'Unknown')

class SimpleGitlabProject():
    def repository_tree(self, path: str = "", ref: str = "",
                        recursive: bool = False, **kwargs: Any) -> List[Dict[str, Any]]:
        
        return [{'name': 'requirements.txt', 'id': 'some_fake_id'}]
        
    def repository_blob(self, sha: str, **kwargs: Any) -> Dict[str, Any]:
        pip_configuration = """requests==2.26.0
pygithub==1.55"""
    
        return {'content': base64.b64encode(pip_configuration.encode('utf-8'))}

class SimpleGitlabProjects():
    def get(self, project_name: str):
        return SimpleGitlabProject()

class SimpleGitlab():
    projects = SimpleGitlabProjects()

    def auth(self):
        pass


if __name__ == '__main__':
    unittest.main()
