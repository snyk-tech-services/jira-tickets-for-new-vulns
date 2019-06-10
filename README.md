
### Simple program pulling the Snyk issues and opening JIRA tickets for those not already having one

## Installation
git clone the repo

## Usage
```
./main 
    -orgID=<SNYK_ORG_ID>                    // Can find it under settings
    -projectID=<SNYK_PROJECT_ID>            // Can find it under project->settings
    -api=<API endpoint>                     // Optional. Default to https://snyk.io/api or to your https://<instance>/api
    -token=<API Token>                      // API Token, either personal (account->Settings) or service account (settings->service account - admin only)
    -jiraProjectID=<12345>                  // Jira project ID the tickets will be opened against
    -severity=<high|medium|low>             // Optional. Severity threshold to open tickets for. Defaults to high.
    -type=<all|vuln|license>                // Optional. Issue type to open tickets for. Defaults to all.
```
## Initial prototype demonstrating usage of Snyk APIs to log Jira tickets programmatically.
### Please report issues.

## Dependencies
https://github.com/michael-go/go-jsn/jsn to make JSON parsing a breeze

### Using NPM?
Check out this package too => https://github.com/snyk/snyk-jira-issue-creator

