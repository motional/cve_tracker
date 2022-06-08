# CVE Tracker Configuration

## Usage

Open the [config.py](config.py) file and define the following items:
* NIST_TOKEN: https://nvd.nist.gov/developers/request-an-api-key

### Searcher Configurations

* search_uri: 
  * GitHubRepoSearcher(`GITHUB_TOKEN`, `project/repo`)
    * GITHUB_TOKEN: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token 
    * project/repo: `PROJECT REPO`

  * GitLabRepoSearcher(`GITLAB_TOKEN`, `gitlab_url`, `project/repo`)
    * GITLAB_TOKEN: https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html
    * gitlab_url: `https://gitlab.com/explore/projects`
    * project/repo: `gitlab-org/gitlab`

  * LocalFileSearcher()


* search_relative_path:  `example/path` optional, defaults to current working directory


* search_pattern:{`FileType`, `PackageParser()`}
  * FileType:
    * `repo.bzl`
    * `package.json`
    * `requirements.txt`
    * `conanfile.py`
    * `sources.json`
    * `sources.csv`

  * PackageParser:
    * `BazelParser()`
    * `CsvParser()`
    * `NpmParser()`
    * `PipParser()`
    * `ConanParser()`
    * `JsonParser()`

### Logging Configurations

* LOGGING_QUIET: Set to `True` if plan to use this without the console display.
* LOGGING_FILE_NAME: Set the logging file name for the logging report to anything you'd like.


### Report Configurations

* REPORT_FILE_NAME: Set the file name for the report to anything you'd like
* REPORT_EXTENSION:
  * `.html`
  * `.json`

* REPORT_VISITOR:
  * `HtmlReportVisitor()`
  * `JsonReportVisitor()`


### Email Configurations
* NOTIFIER: set `NOTIFIER` to `EmailNotifier()`, otherwise keep the default of `None` for no notification.

*Note: If you'd like to receive email notifications, you must also configure the following fields:
* HOST = `smtp.email-domain.com`
* SENDER = `security@company.com`
* RECIPIENT = `john.doe@company.com, jane.doe@company.com`