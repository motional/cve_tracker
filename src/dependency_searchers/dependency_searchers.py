"""
This module provides the functionality required to (1) find files that specify
dependencies in particular datastores and (2) pass their contents to the appropriate
parser. The following datastores are currently supported:

- GitHub repositories
- GitLab repositories
- The local filesystem
"""

import base64
from abc import abstractmethod, ABCMeta
from typing import List, Dict
import glob
import logging
import os
import pathlib
from requests.exceptions import ConnectionError as GitLabConnectionError
import gitlab
from gitlab import GitlabAuthenticationError, GitlabParsingError
from github import Github, BadCredentialsException, UnknownObjectException
from src.dependency_searchers.package_parsers import PackageParser


class DependencySearcher(metaclass=ABCMeta):
    """
    Dependency searchers are used to find package (A.K.A. configuration or
    manifest) files that match a particular pattern specified by a Python
    regex. Matched files are read and their contents are passed to the
    appropriate parser. The parser returns the dependencies specified by the
    file. A searcher supports one particular type of datastore, such as the
    local filesystem, a GitHub repository, etc.
    """

    @abstractmethod
    def search(self, search_pattern: Dict[str, PackageParser],
               search_path=".") -> List[Dict[str, str]]:

        """
        Search the datastore for file names that match a regex. Matched files
        are passed to a parser mapped to the regex. The parser returns the
        dependency list this method returns.

        Args:
            search_pattern (Dict[str, PackageParser]): A dictionary that maps
                file patterns (regexs) to the parser to use for each pattern
            search_path (str, optional): the location in the datastore to
                start searching in. Defaults to the current working directory
                or root depending on the type of datastore

        Returns:
            list: a list of dictionaries, where each dictionary contains dependency
                metadata found in matched files
        """
        raise NotImplementedError("You did not implement the search method")


class GitHubRepoSearcher(DependencySearcher):
    """ This class is used to search a GitHub repository for package files and
        returns dependencies parsed from them. """

    def __init__(self, token: str, repo_name: str):
        self._token = token
        self._repo_name = repo_name
        self._repo = None

    def _get_contents(self, search_path: str) -> List:
        contents = []

        if not self._repo:
            try:
                self._repo = Github(self._token).get_repo(self._repo_name)
            except BadCredentialsException:
                logging.error("Failed to authenticate to GitHub. "
                              "The specified token is likely wrong.")
                return contents
            except UnknownObjectException:
                logging.error("The repository %s does not exist on GitHub.", self._repo_name)
                return contents

        try:
            contents = self._repo.get_contents(search_path)
        except UnknownObjectException:
            logging.error("The search path %s does not exist in the GitHub repository %s.",
                          search_path, self._repo_name)

        return contents

    def search(self, search_pattern: Dict[str, PackageParser], search_path="") -> List[Dict[str, str]]:
        dependencies = []
        contents = self._get_contents(search_path)

        for file_content in contents:
            if file_content.type == "dir":
                contents.extend(self._get_contents(file_content.path))
                continue

            filename = file_content.path
            if '/' in filename:
                filename = filename[filename.rindex('/') + 1:]

            for pattern in search_pattern.keys():
                if pathlib.PurePath(filename).match(pattern):
                    package_dependencies = search_pattern[pattern] \
                                               .parse(file_content.decoded_content)
                    dependencies.extend(package_dependencies)

        return dependencies


class GitLabRepoSearcher(DependencySearcher):
    """ This class is used to search a GitLab repository for package files and
        returns dependencies parsed from them. """

    def __init__(self, token: str, gitlab_url: str, project: str):
        self._token = token
        self._gitlab_url = gitlab_url
        self._project = project

    def search(self, search_pattern: Dict[str, PackageParser],
               search_path="") -> List[Dict[str, str]]:

        dependencies = []
        client = gitlab.Gitlab(self._gitlab_url, self._token)

        try:
            client.auth()
            project = client.projects.get(self._project)
            repository_files = project.repository_tree(search_path,
                                                     recursive=True, all=True)
            if repository_files:
                for repository_file in repository_files:
                    for pattern in search_pattern.keys():
                        if pathlib.PurePath(repository_file['name']).match(pattern):
                            info = project.repository_blob(repository_file['id'])
                            file_data = str(base64.b64decode(info['content']).decode('utf-8'))
                            package_dependencies = search_pattern[pattern].parse(file_data)
                            dependencies.extend(package_dependencies)
            else:
                logging.error("Failed to find %s. "
                              "The specified search path is likely wrong.", search_path)
        except (GitlabAuthenticationError, GitLabConnectionError, GitlabParsingError):
            logging.error("Failed to authenticate to %s. "
                          "The specified token is likely wrong.", self._gitlab_url)
        except gitlab.exceptions.GitlabGetError:
            logging.error("Failed to find %s. "
                          "The specified project is likely wrong.", self._project)
        return dependencies


class LocalFileSearcher(DependencySearcher):
    """ This class is used to search the local filesystem for package files and
        returns dependencies parsed from them. """

    def search(self, search_pattern: Dict[str, PackageParser],
               search_path=".") -> List[Dict[str, str]]:
        dependencies = []

        for dependency_package in glob.glob(search_path + '/**', recursive=True):
            filename = os.path.basename(dependency_package)

            for pattern in search_pattern.keys():
                if pathlib.PurePath(filename).match(pattern):
                    with open(dependency_package, 'r') as dependency_file:
                        parsed_dependencies = search_pattern[pattern].parse(dependency_file.read())
                        dependencies.extend(parsed_dependencies)

        return dependencies
