
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
    -jiraProjectKey=<Key>                  // Jira project Key the tickets will be opened against
```
### Extended options
```
./snyk-jira-sync-<yourplatform> 
    -orgID=<SNYK_ORG_ID>                                                // Can find it under settings
    -projectID=<SNYK_PROJECT_ID>                                        // Optional. Syncs all projects in Organization if not provided.
                                                                        // Project ID can be found under project->settings
    -api=<API endpoint>                                                 // Optional. Set to https://<instance>/api for private instances
    -token=<API Token>                                                  // Snyk API Token. Service accounts work.
    -jiraProjectID=<12345>                                              // Jira project ID the tickets will be opened against
    -jiraProjectKey=<KEY>                                               // Jira project Key the tickets will be opened against
    -jiraTicketType=<Task|Bug|....>                                     // Optional. Type of ticket to open. Defaults to Bug
    -severity=<critical|high|medium|low>                                // Optional. Severity threshold to open tickets for. Defaults to low.
    -maturityFilter=[mature,proof-of-concept,no-known-exploit,no-data]  // Optional. include only maturity level(s). Separated by commas
    -type=<all|vuln|license>                                            // Optional. Issue type to open tickets for. Defaults to all.
    -assigneeId=<123abc456def789>                                       // Optional.  Jira ID of user to assign tickets to. Note: Do not use assigneeName and assigneeId at the same time
    -assigneeName=<AccountName>                                         // Optional.  Jira Name of user to assign tickets to. Note: Do not use assigneeName and assigneeId at the same time
    -priorityIsSeverity                                                 // Optional. Set the ticket priority to be based on severity (defaults: Low|Medium|High|Critical=>Low|Medium|High|Highest)
    -labels=<IssueLabel1>,IssueLabel2                                   // Optional. Set JIRA ticket labels
    -priorityScoreThreshold=[0-1000]                                    // Optional. Your min priority score threshold
    -dryRun=<true|false>                                                // Optional. result can be found in a json file were the tool is run
    -debug=<true|false>                                                 // Optional. enable debug mode
```

### Priority is Severity
Option to get the JIRA ticket priority set based on issue severity.
Defaults map to:

Issue severity | JIRA Priority
----- | -----
critical | Highest
high | High
medium | Medium
low | Low

Use SNYK_JIRA_PRIORITY_FOR_XXX_VULN env var to override the default an set your value.
> Example:
> Critical sevs should receive the Hot Fix priority in JIRA
>
> export SNYK_JIRA_PRIORITY_FOR_CRITICAL_VULN='Hot Fix'

## Installation from source
git clone the repo, build.
> `go run main.go jira.go jira_utils.go vulns.go snyk.go snyk_utils.go`


### Please report issues.

## Dependencies
https://github.com/michael-go/go-jsn/jsn to make JSON parsing a breeze
github.com/tidwall/sjson
github.com/kentaro-m/blackfriday-confluence
gopkg.in/russross/blackfriday.v2


