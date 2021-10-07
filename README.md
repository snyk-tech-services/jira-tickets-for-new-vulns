
### Sync your Snyk monitored projects and open automatically JIRA tickets for new issues and existing one(s) without ticket already created.
>Note: 
Copy the script below and modify the orgID, projectID, token, jiraProjectID, jiraTicketType and create a bash file.

>Cron it every X minutes/hours and fix the issues.

>Aimed to be executed at regular interval or with a trigger of your choice (webhooks).


[![CircleCI](https://circleci.com/gh/snyk-tech-services/jira-tickets-for-new-vulns.svg?style=svg)](https://circleci.com/gh/snyk-tech-services/jira-tickets-for-new-vulns)

## Installation
Use the appropriate binary from [the release page](https://github.com/snyk-tech-services/jira-tickets-for-new-vulns/releases)


## Usage - Quick start
```
./snyk-jira-sync-<yourplatform> 
    --orgID <SNYK_ORG_ID>                    // Can find it under settings
    --projectID <Snyk Project ID>            // Can find it in the URL of the project or via API
    --token <API Token>                      // Snyk API Token. Service accounts work.
    --jiraProjectID <12345>                  // Jira project ID the tickets will be opened against
    --jiraTicketType <Ticket Type in jira>   // Find this in Jira
```
## Script Parameters:
```
- To find the orgID, go to Snyk -> Settings

- To find the projectID go to Snyk -> Select the desired Project -> Grab the UUID from the URL

- Snyk API token -> You should already have this but if you do not, go to Snyk -> Settings -> Service Accounts -> Create 

- jiraProjectID -> This is from Jira and is an integer. To find this, go to https://your-domain.atlassian.net/rest/api/3/project and under the ID key, you will see the ProjectID integer

- jiraTicketType -> This is from Jira and can be found in Projects -> Project Settings -> Issue types
```

## Example 
>Note: in this example, I am using macOS, an orgID of 6ad83e4e-099b-4dc4-ac2d-4b449ef61f40, a projectID of 86efd136-30e9-4546-94c1-5e7fc7b67574, a jiraProjectID of 10000 and opening Task tickets in Jira: 

1. Download the macOS .bin
2. Run the script using the following command 

```./snyk-jira-sync-macos --orgID  6ad83e4e-099b-4dc4-ac2d-4b449ef61f40 --projectID 86efd136-30e9-4546-94c1-5e7fc7b67574 --token <Snyk API Token> --jiraProjectID 10000 --jiraTicketType Task```

### Extended options
```
./snyk-jira-sync-<yourplatform> 
    -orgID=<SNYK_ORG_ID>                                                // Can find it under settings
    -projectID=<SNYK_PROJECT_ID>                                        // Optional. Syncs all projects in Organization if not provided.
                                                                        // Project ID can be found under project->settings
    -api=<API endpoint>                                                 // Optional. Set to https://<instance>/api for private instances
    -token=<API Token>                                                  // Snyk API Token. Service accounts work.
    -jiraProjectID=<12345>                                              // Jira project ID the tickets will be opened against
    -jiraTicketType=<Task|Bug|....>                                     // Optional. Type of ticket to open. Defaults to Bug
    -severity=<critical|high|medium|low>                                // Optional. Severity threshold to open tickets for. Defaults to low.
    -maturityFilter=[mature,proof-of-concept,no-known-exploit,no-data]  // Optional. include only maturity level(s). Separated by commas
    -type=<all|vuln|license>                                            // Optional. Issue type to open tickets for. Defaults to all.
    -assigneeId=<123abc456def789>                                       // Optional.  Jira ID of user to assign tickets to.
    -priorityIsSeverity                                                 // Optional. Set the ticket priority to be based on severity (defaults: Low|Medium|High|Critical=>Low|Medium|High|Highest)
    -labels=<IssueLabel1>,IssueLabel2                                   // Optional. Set JIRA ticket labels
    -priorityScoreThreshold=[0-1000]                                    // Optional. Your min priority score threshold
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


