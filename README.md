
### Sync your Snyk monitored projects and open automatically JIRA tickets for new issues and existing one(s) without ticket already created.
Cron it every X minutes/hours and fix the issues.
Aimed to be executed at regular interval or with a trigger of your choice (webhooks).


[![CircleCI](https://circleci.com/gh/snyk-tech-services/jira-tickets-for-new-vulns.svg?style=svg)](https://circleci.com/gh/snyk-tech-services/jira-tickets-for-new-vulns)

## Installation
Use the binaries from [the release page](https://github.com/snyk-tech-services/jira-tickets-for-new-vulns/releases)

## Usage - Quick start
```
./snyk-jira-sync-<yourplatform> 
    -orgID=<SNYK_ORG_ID>                    // Can find it under settings
    -token=<API Token>                      // Snyk API Token. Service accounts work.
    -jiraProjectID=<12345>                  // Jira project ID the tickets will be opened against
```
### Extended options
```
./snyk-jira-sync-<yourplatform> 
    -orgID=<SNYK_ORG_ID>                    // Can find it under settings
    -projectID=<SNYK_PROJECT_ID>            // Optional. Syncs all projects in Organization if not provided.
                                            // Project ID can be found under project->settings
    -api=<API endpoint>                     // Optional. Set to https://<instance>/api for private instances
    -token=<API Token>                      // Snyk API Token. Service accounts work.
    -jiraProjectID=<12345>                  // Jira project ID the tickets will be opened against
    -jiraTicketType=<Task|Bug|....>         // Optional. Type of ticket to open. Defaults to Bug
    -severity=<high|medium|low>             // Optional. Severity threshold to open tickets for. Defaults to low.
    -type=<all|vuln|license>                // Optional. Issue type to open tickets for. Defaults to all.
```

## Installation from source
git clone the repo, build.

### Please report issues.

## Dependencies
https://github.com/michael-go/go-jsn/jsn to make JSON parsing a breeze
github.com/tidwall/sjson
github.com/kentaro-m/blackfriday-confluence
gopkg.in/russross/blackfriday.v2


