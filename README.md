
### Sync your Snyk monitored projects and open automatically JIRA tickets for new issues and existing one(s) without ticket already created.
Cron it every X minutes/hours and fix the issues.
Aimed to be executed at regular interval or with a trigger of your choice (webhooks).


[![CircleCI](https://circleci.com/gh/snyk-tech-services/jira-tickets-for-new-vulns.svg?style=svg)](https://circleci.com/gh/snyk-tech-services/jira-tickets-for-new-vulns)
[![Not Maintained](https://img.shields.io/badge/Maintenance%20Level-Not%20Maintained-yellow.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)

**This repository is not in active developemnt and critical bug fixes only will be considered.**

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
    --orgID=<SNYK_ORG_ID>                                                // Can find it under settings
    --projectID=<SNYK_PROJECT_ID>                                        // Optional. Syncs all projects in Organization if not provided.
                                                                        // Project ID can be found under project->settings
    --api=<API endpoint>                                                 // Optional. Set to https://<instance>/api for private instances
    --token=<API Token>                                                  // Snyk API Token. Service accounts work.
    --jiraProjectID=<12345>                                              // Jira project ID the tickets will be opened against
    --jiraProjectKey=<KEY>                                               // Jira project Key the tickets will be opened against
    --jiraTicketType=<Task|Bug|....>                                     // Optional. Type of ticket to open. Defaults to Bug. Please see the 'Notes' section below.
    --severityThreshold=<critical|high|medium|low>                       // Optional. Severity threshold to open tickets for. Defaults to low.
    --severities=[critical,high,medium,low]                              // Optional. Your severity array, to be used for multiple or specific severity
    --maturityFilter=[mature,proof-of-concept,no-known-exploit,no-data]  // Optional. include only maturity level(s). Separated by commas
    --type=<all|vuln|license>                                            // Optional. Issue type to open tickets for. Defaults to all.
    --assigneeId=<123abc456def789>                                       // Optional.  Jira ID of user to assign tickets to. Note: Do not use assigneeName and assigneeId at the same time
    --assigneeName=<AccountName>                                         // Optional.  Jira Name of user to assign tickets to. Note: Do not use assigneeName and assigneeId at the same time
    --priorityIsSeverity                                                 // Optional. Set the ticket priority to be based on severity (defaults: Low|Medium|High|Critical=>Low|Medium|High|Highest)
    --labels=<IssueLabel1>,IssueLabel2                                   // Optional. Set JIRA ticket labels
    --priorityScoreThreshold=[0-1000]                                    // Optional. Your min priority score threshold
    --dryRun=<true|false>                                                // Optional. result can be found in a json file were the tool is run
    --debug=<true|false>                                                 // Optional. enable debug mode
    --ifUpgradeAvailableOnly=<true|false>                                // Optional. create ticket only for upgradable issues
    --configFile                                                         // Path the jira.yaml if not root 
```

## Restrictions
The tool does not support IAC project. It will open issue only for code and open source projects and ignore all other project type.

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

## LogFile
A logFile listing all the tickets created can be found where the tool has been run.

```
{
  "projects": {
    "123": [
      {
        "Summary": "test/goof:package.json - Remote Code Execution (RCE)",
        "Description": "\r\n \\*\\*\\*\\* Issue details: \\*\\*\\*\\*\n\r\n cvssScore:  8.10\n exploitMaturity:  proof\\-of\\-concept\n severity:  high\n pkgVersions: 3.0.0\\]\n\r\n*Impacted Paths:*\n\\- \"snyk\"@\"1.228.3\" =\u003e \"proxy\\-agent\"@\"3.1.0\" =\u003e \"pac\\-proxy\\-agent\"@\"3.0.0\" =\u003e \"pac\\-resolver\"@\"3.0.0\"\n\r\n[See this issue on Snyk|https://app.snyk.io/org/test/project/123]\n\n[More About this issue|https://snyk.io/vuln/SNYK-JS-PACRESOLVER-1589857]\n\n",
        "JiraIssueDetail": {
          "JiraIssue": {
            "Id": "10001",
            "Key": "FPI-001"
          },
          "IssueId": "SNYK-JS-PACRESOLVER-1589857"
        }
      },
      {
        "Summary": "test/goof:package.json - Prototype Pollution",
        "Description": "\r\n \\*\\*\\*\\* Issue details: \\*\\*\\*\\*\n\r\n cvssScore:  6.30\n exploitMaturity:  proof\\-of\\-concept\n severity:  medium\n pkgVersions: 4.2.0\\]\n\r\n*Impacted Paths:*\n\\- \"snyk\"@\"1.228.3\" =\u003e \"configstore\"@\"3.1.2\" =\u003e \"dot\\-prop\"@\"4.2.0\"\n\r\\- \"snyk\"@\"1.228.3\" =\u003e \"update\\-notifier\"@\"2.5.0\" =\u003e \"configstore\"@\"3.1.2\" =\u003e \"dot\\-prop\"@\"4.2.0\"\n\r\n[See this issue on Snyk|https://app.snyk.io/org/test/project/123]\n\n[More About this issue|https://snyk.io/vuln/SNYK-JS-DOTPROP-543499]\n\n",
        "JiraIssueDetail": {
          "JiraIssue": {
            "Id": "10001",
            "Key": "FPI-001"
          },
          "IssueId": "SNYK-JS-DOTPROP-543499"
        }
      },
    ]
  }
}
```

## Jira.yaml

Example of config file structure. 
If your jira project has specific mandatory field or custom fields configured, they will need to be added to the config file.
Mandatory fields: 
  - Make sure to give both key and value expected by jira under the customMandatoryField key of the config file.
  We support 2 kind of mandatory field: simple key/value pair or nested key/value
  
  - Simple key/Value:
    
    ``` 
      customMandatoryFields:
            key: 
              value: "This is a summary" 
    ```
    will result in adding this object to the ticket ``` {"key":{"Value":"This is a summary"} ```
  
  - Nested:
    ``` 
    firstKey:
          secondKey: 
            id: 65 
    ```
    will result in adding this object to the ticket ``` "firstKey":{"secondKey":{"id":62}} ```


Custom fields:
  - At the moment we are supporting 3 types of custom fields: labels, MultiGroupPicker and MultiSelect.
  - Make sure to respect the format belong in the config file:
    - labels:
      ``` "customfield_10601": jiraValue-label-Value1,Value2``` => ``` "customfield_10601":["Value1","Value2"]```
    - MultiGroupPicker:
      ``` "customfield_10601": jiraValue-MultiGroupPicker-Value1,Value2``` => ``` "customfield_10601":[{"name":"Value1"},{"name":"Value2"}]```
    - MultiGroupPicker:
      ``` "customfield_10601": jiraValue-MultiSelect-Value1,Value2```  => ``` "customfield_10601":[{"value":"Value1"},{"value":"Value2"}]```

For more details on jira custom field please visit [Jira documentation] (https://developer.atlassian.com/server/jira/platform/jira-rest-api-example-create-issue-7897248/)

```
schema: 1
snyk: 
    orgID: a1b2c3de-99b1-4f3f-bfdb-6ee4b4990513 # <SNYK_ORG_ID> 
    projectID: a1b2c3de-99b1-4f3f-bfdb-6ee4b4990514 # <SNYK_PROJECT_ID>
    severityThreshold: critical # <critical|high|medium|low> defaults to low
    severities: low # <critical,high,medium,low>
    maturityFilter: mature # <mature,proof-of-concept,no-known-exploit,no-data>
    type: all # <all|vuln|license>
    priorityScoreThreshold: 10
    api: https://myapi # <API endpoint> default to 
    ifUpgradeAvailableOnly: false # <true|false>
jira:
    jiraTicketType: Task # <Task|Bug|....>
    jiraProjectID: 12345
    assigneeId: 123abc456def789
    assigneeName: AccountName
    priorityIsSeverity: true # <true|false>
    labels: label1 # <IssueLabel1>,<IssueLabel2>
    jiraProjectKey: testProject
    priorityIsSeverity: false # <true|false> (defaults: Low|Medium|High|Critical=>Low|Medium|High|Highest)
    customMandatoryFields:
        key: 
            value: 5
    customfield_10601: jiraValue-MultiGroupPicker-Value1,Value2
```

Notes: 
  - The token is not expected present in the config file
  - Command line arguments override the config file. IE: 
      Using the config file above, running ./snyk-jira-sync-macOs -Org=1234 -configFile=true -token=123
      the org ID used by the tool will be 1234 and not a1b2c3de-99b1-4f3f-bfdb-6ee4b4990513
  - See 'Extended options' for default values 
  - Please ensure you use the same issue type that is configured in your JIRA. Default is Bug. Please verify the type is use (or default) exists in your JIRA configuration.

