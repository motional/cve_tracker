import os
import datetime
from src.dependency_searchers.dependency_searchers import LocalFileSearcher, \
    GitLabRepoSearcher, \
    GitHubRepoSearcher
from src.dependency_searchers.package_parsers import BazelParser, CsvParser, \
    NpmParser, PipParser, \
    ConanParser, JsonParser
from src.report_creators.html_report_visitor import HtmlReportVisitor
from src.report_creators.json_report_visitor import JsonReportVisitor
from src.notification.email import EmailNotifier


class Config:
    """
    In this class you configure:
        1. Your NIST API key (optional) to enable rapid National Vulnerability Database queries
        2. The dependency searchers you want to use to find dependencies to monitor for CVEs
        3. The type of report you want generated should CVEs exist in discovered dependencies
        4. The way to provide notifications to responsible parties when new CVEs are found in
           your dependencies

    Dependency searchers search a particular type of data store for package files that store
    metadata about dependencies. You can search GitHub (GitHubRepoSearcher),
    GitLab (GitLabRepoSearcher), or a local file system (LocalFileSearcher).

    Dependency searchers get paired with file pattern to package parser mappings, which
    configure the types of package files the searcher should find and the parsers that should be
    used to fetch the dependencies they define. The following package parsers are available:

        * BazelParser() - For Bazel build system dependency definitions.
            Example search pattern: {"repo.bzl": BazelParser()}
        * ConanParser() - For Conan package files.
            Example search pattern: {"conanfile.py": ConanParser()}
        * CsvParser() - For CVE Tracker-specific CSV files.
            Example search pattern: {"sources.csv": CsvParser()}
        * NpmParser() - For NPM package files.
            Example search pattern: {"package.json": NpmParser()}
        * PipParser() - For PIP package files.
            Example search pattern: {"requirements.txt": PipParser()}
        * JsonParser() - For json package files.
            Example search pattern: {"sources.json": JsonParser()}

    When your dependencies have assigned CVEs, this tool produces either an HTML or JSON report
    when the HtmlReportVisitor() or JsonReportVisitor() are configured. You can choose to have a
    notice summarizing new CVEs sent via email by configuring the EmailNotifier() or to have no
    notice sent.
    """

    """
    Learn more about the NIST API key here: https://nvd.nist.gov/developers/request-an-api-key
    Leave this option blank if you do not want to request a NIST API key. However, NIST rate
    limits requests without an API key to 10 requests in a rolling 60 second window. The rate
    limit with an API key is 100 requests in a rolling 60 second window.
    """
    NIST_TOKEN = ''

    """
    Configure any combination of dependency search_uri and package parsers below. Note that
    search patterns are Python regular expressions, which allows for quite a bit of flexibility
    when configuring what package files to find and parse. You can configure any number of
    pattern to parser mappings per search_uri configuration. Only search_uri configurations appended
    to the SEARCHER_CONFIGS list will be used.

    GitHub tokens are documented here:
    https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token
    GitHub configuration example:
     SEARCHER_CONFIGS.append({
         "search_uri": GitHubRepoSearcher("github_token_here", "project/repo"),
         "search_relative_path": "example/path", # optional, defaults to current working directory
         "search_pattern": {"package.json": NpmParser(),
                            "*.bzl": BazelParser()}
         })

    GitLab tokens are documented here:
    https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html
    GitLab configuration example:
     SEARCHER_CONFIGS.append({
            "search_uri": GitLabRepoSearcher("gitlab_token_here", "gitlab_url_here", "project/repo"),
            "search_relative_path": "example/path", # optional, defaults to current working directory
            "search_pattern": {"repo.bzl": BazelParser()}
            })

    Local file configuration example:
     SEARCHER_CONFIGS.append({
         "search_uri": LocalFileSearcher(),
         "search_relative_path": "example/path", # optional, defaults to current working directory
         "search_pattern": {"sources.csv": CsvParser()}
         })

    """
    SEARCHER_CONFIGS = []
    SEARCHER_CONFIGS.append({
        "search_uri": '',
        "search_relative_path": '',
        "search_pattern": {"": {}},

    })

    """
    Set the LOGGING_QUIET to True if plan to use this without the console display. 
    Set the logging file name for the logging report to anything you'd like by setting LOGGING_FILE_NAME.
    """
    LOGGING_QUIET = False
    LOGGING_FILE_NAME = 'logging/logging_report_' + str(datetime.datetime.now())

    """
    Set the file name for the report to anything you'd like by setting REPORT_FILE_NAME.
    If you switch away from the default, we recommend including a timestamp to avoid overwriting
    older reports.

    The REPORT_EXTENSION option sets the file extension for the report. We recommend using
    .html or .json depending on the visitor used.

    The REPORT_VISITOR defines the type of report that will be generated. Both HTML
    (HtmlReportVisitor()) and JSON (JsonReportVisitor()) are supported.
    """
    CURRENT_DIRECTORY = os.path.dirname(__file__)
    TOP_DIRECTORY = os.path.dirname(CURRENT_DIRECTORY)
    REPORT_DIRECTORY = TOP_DIRECTORY + '/reports'
    REPORT_FILE_NAME = 'cve_report_' + str(datetime.datetime.now())
    REPORT_FILE_PATH = os.path.join(REPORT_DIRECTORY, REPORT_FILE_NAME)
    REPORT_EXTENSION = '.html'
    REPORT_VISITOR = HtmlReportVisitor()

    """
    To produce an email notification set NOTIFIER to EmailNotifier(), otherwise keep
    the default of None for no notification.

    If you'd like to receive email notifications, you must also configure the following fields:

    HOST = 'smtp.email-domain.com'
    SENDER = 'security@company.com'
    RECIPIENT = 'john.doe@company.com, jane.doe@company.com'
    """
    NOTIFIER = None 
