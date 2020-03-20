
### Simple program pulling the Snyk issues and opening JIRA tickets for those not already having one
Aimed to be executed at regular interval or with a trigger of your choice.

[![CircleCI](https://circleci.com/gh/snyk-tech-services/jira-tickets-for-new-vulns.svg?style=svg)](https://circleci.com/gh/snyk-tech-services/jira-tickets-for-new-vulns)

## Installation
git clone the repo

## Usage
```
./snyk-jira-sync-<yourplatform> 
    -orgID=<SNYK_ORG_ID>                    // Can find it under settings
    -projectID=<SNYK_PROJECT_ID>            // Can find it under project->settings
    -api=<API endpoint>                     // Optional. Default to https://snyk.io/api or to your https://<instance>/api
    -token=<API Token>                      // API Token, either personal (account->Settings) or service account (settings->service account - admin only)
    -jiraProjectID=<12345>                  // Jira project ID the tickets will be opened against
    -jiraTicketType=<Task|Bug|....>         // Type of ticket to open. Defaults to Bug
    -severity=<high|medium|low>             // Optional. Severity threshold to open tickets for. Defaults to low.
    -type=<all|vuln|license>                // Optional. Issue type to open tickets for. Defaults to all.
```
### Please report issues.

## Dependencies
https://github.com/michael-go/go-jsn/jsn to make JSON parsing a breeze
github.com/tidwall/sjson
github.com/kentaro-m/blackfriday-confluence
gopkg.in/russross/blackfriday.v2

### Using NPM?
Check out this package too => https://github.com/snyk/snyk-jira-issue-creator

