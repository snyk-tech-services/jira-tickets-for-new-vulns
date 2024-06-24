
### Open Jira tickets for new & existing Snyk project issues

Sync your Snyk monitored projects and open automatically JIRA tickets for new issues and existing one(s) without ticket already created.
Run this after `snyk monitor` in CI or every day/hour for non CLI projects.
Aimed to be executed at regular interval or with a trigger of your choice (webhooks).


[![CircleCI](https://circleci.com/gh/snyk-tech-services/jira-tickets-for-new-vulns.svg?style=svg)](https://circleci.com/gh/snyk-tech-services/jira-tickets-for-new-vulns)
[![Inactively Maintained](https://img.shields.io/badge/Maintenance%20Level-Inactively%20Maintained-yellowgreen.svg)](https://gist.github.com/cheerfulstoic/d107229326a01ff0f333a1d3476e068d)


**This repository is in maintenance mode, no new features are being developed. Bug & security fixes will continue to be delivered. Open source contributions are welcome for small features & fixes (no breaking changes)**

## Installation
You can either download the binaries from the [the release page](https://github.com/snyk-tech-services/jira-tickets-for-new-vulns/releases)
or
Use `go install github.com/snyk-tech-services/jira-tickets-for-new-vulns@latest`

## Usage - Quick start
- `--orgID` *required*

  Public Snyk organization ID can be located in the [organization settings](https://docs.snyk.io/products/snyk-code/cli-for-snyk-code/before-you-start-set-the-organization-for-the-cli-tests/finding-the-snyk-id-and-internal-name-of-an-organization)

  *Example*: `--orgID=0e9373a6-f858-11ec-b939-0242ac120002`
- `--token` *required*

  Create a [service account](https://docs.snyk.io/features/user-and-group-management/managing-groups-and-organizations/service-accounts) in Snyk and use the provided token.

  *Example*: `--token=0e9373a6-f858-11ec-b939-0242ac120002`

- `--jiraProjectKey` *required*

  [Jira project key](https://confluence.atlassian.com/jirakb/how-to-get-project-id-from-the-jira-user-interface-827341414.html) the tickets will be opened against.

  *Example*: `--jiraProjectKey=TEAM_A`


*Example*:
```
./snyk-jira-sync-linux --orgID=0e9373a6-f858-11ec-b939-0242ac120002 --token=xxxxxxxx-xxxx-xxxx-xxxx-0242ac120002 --jiraProjectKey=TEAM_A
```

### Extended options
- `--orgID` *required*

  Public Snyk organization ID can be located in the [organization settings](https://docs.snyk.io/products/snyk-code/cli-for-snyk-code/before-you-start-set-the-organization-for-the-cli-tests/finding-the-snyk-id-and-internal-name-of-an-organization)

  *Example*: `--orgID=0e9373a6-f858-11ec-b939-0242ac120002`
- `--token` *required*

  Create a [service account](https://docs.snyk.io/features/user-and-group-management/managing-groups-and-organizations/service-accounts) in Snyk and use the provided token.

  *Example*: `--token=0e9373a6-f858-11ec-b939-0242ac120002`

- `--jiraProjectKey` *required*

  [Jira project key](https://confluence.atlassian.com/jirakb/how-to-get-project-id-from-the-jira-user-interface-827341414.html) the tickets will be opened against.

  *Example*: `--jiraProjectKey=TEAM_A`

- `--jiraProjectID` *optional*

  `jiraProjectKey` or `jiraProjectID` must be set, but not both. This is an alternative way to specify a Jira project.

  *Example*: `--jiraProjectKey=1234`

- `--projectID` *optional*

  By default all projects in a given Snyk organization will be synced, if `projectID` is set only this project will be synced. Project public ID can be located in [project settings](https://docs.snyk.io/introducing-snyk/introduction-to-snyk-projects/view-project-settings)

  *Example*: `--projectID=0e9373a6-f858-11ec-b939-0242ac120002`

- `--api` *optional*

  Alternative API host.

  Example: `--api=https://my.private.instance.com/api`
- `--jiraTicketType` *optional*

  Type of ticket to open. Defaults to `Bug`. Must match the issue type configured in the provided Jira project.

  *Example*: `--jiraTicketType=Defect`
- `--severity` *optional*

  Severity threshold to open tickets for. Can be one of `critical`, `high`, `medium`, `low`. Defaults to `low`.
  *Example*: `--severity=critical`
- `--maturityFilter` *optional*

  Can be one or multiple values: `mature`, `proof-of-concept`, `no-known-exploit`, `no-data`. **Note: Not supported for Snyk Code**

  *Example*: `--maturityFilter=[mature,no-data]`
- `--type` *optional*

  Snyk issue type to open tickets for. Defaults to `all`. Possible values: `all`, `vuln`, `license`

  *Example*: `--type=vuln`
- `--assigneeId` *optional*

  [Jira ID of user](https://community.atlassian.com/t5/Jira-questions/How-do-I-find-my-account-ID/qaq-p/1702795#:~:text=Click%20your%20Profile%20menu%20in,people%2F%20is%20your%20account%20ID.&text=p.s.%20of%20course%20this%20is%20a%20manual%20way%20to%20check%20user%20IDs.&text=Ah%2C%20for%20some%20reason%20I%20thought%20you%20were%20on%20Jira%20Cloud!) to assign tickets to.

  *Example*: `--assigneeId=123abc456def789`
- **DEPRECATED** `--assigneeName` *optional*

  Currently Snyk supports Jira API v2 where this field is now deprecated. See the [Jira deprecation notice](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-user-privacy-api-migration-guide/).
- `--priorityIsSeverity` *optional*

  Set the ticket priority to be based on severity, default priorities & severities: `Low|Medium|High|Critical=>Low|Medium|High|Highest`. Can be `true` or ` false`.

  *Example*: `--priorityIsSeverity=true`

- `--labels` *optional*

  Set [Jira ticket labels](https://confluence.atlassian.com/jirasoftwareserver/editing-and-collaborating-on-issues-939938928.html)

  *Example*: `--labels=app-1234`

- `--dueDate` *optional*

  Set [Jira ticket labels](https://confluence.atlassian.com/jirasoftwareserver/editing-and-collaborating-on-issues-939938928.html)

  *Example*: `--dueDate=2022-12-01`
-
- `--priorityScoreThreshold` *optional*

  Your minimum [Snyk priority score](https://docs.snyk.io/features/fixing-and-prioritizing-issues/starting-to-fix-vulnerabilities/snyk-priority-score) threshold. Can be a number between `0` and `1000`.

  *Example*: `--priorityScoreThreshold=700`
[0-1000]
- `--dryRun` *optional*

  Enables dry run mode, which will not open any tickets but provide information on what changes will occur. Results can be found in a json log file in the same directory.

  *Example*: `--dryRun=true`

- `--debug` *optional*

  Enables debug mode. For more comprehensive debug information from Go set the environment variable `GODEBUG=http2debug=2` as well.

  *Example*: `--debug=true`

- `--cveInTitle` *optional*

  Enables the CVEs as suffix in the Jira ticket title.

  *Example*: `--cveInTitle=true`
  **Note: Not supported for Snyk Code**

- `--ifUpgradeAvailableOnly` *optional*

  Only create tickets for `vuln` issues that are upgradable.`--type` must be set to `all` or `vuln` for this to work.

  *Example*: `--ifUpgradeAvailableOnly=true`

- `--projectCriticality` *optional*

  Include only projects whose [Snyk business criticality attribute](https://docs.snyk.io/introducing-snyk/introduction-to-snyk-projects/view-project-information/project-attributes#business-criticality) contains one or more of the specified values. This should be all lower case, comma separated with no spaces.

  *Example*: `--projectCriticality=critical,medium`

- `--projectEnvironment` *optional*

  Include only projects whose [Snyk environment attribute](https://docs.snyk.io/introducing-snyk/introduction-to-snyk-projects/view-project-information/project-attributes#environment) contains one or more of the specified values. This should be all lower case, comma separated with no spaces.

  *Example*: `--projectEnvironment=backend,frontend`

- `--projectLifecycle` *optional*

  Include only projects whose [Snyk lifecycle attribute](https://docs.snyk.io/introducing-snyk/introduction-to-snyk-projects/view-project-information/project-attributes#lifecycle-stage) contains one or more of the specified values. This should be all lower case, comma separated with no spaces.

  *Example*: `--projectLifecycle=development,production`

- `--configFile` *optional*

  Path the directory where `jira.yaml` file is located (by default we will check current directory)

  *Example*: `--configFile=/directory-name`

- `--ifAutoFixableOnly` *optional*

  Only create tickets for `vuln` issues that are fixable (no effect when using `ifUpgradeAvailableOnly`).`--type` must be set to `all` or `vuln` for this to work.

  *Example*: `--ifAutoFixableOnly=true`

## Restrictions
The tool does not support IAC project. It will open issue only for code and open source projects and ignore all other project type.

### Priority is Severity
Option to get the JIRA ticket priority set based on issue severity.
Defaults map to:

|  Issue severity  | JIRA priority |
|:----------------:|:-------------:|
|     critical     |    Highest    |
|       high       |     High      |
|      medium      |    Medium     |
|       low        |      Low      |

Use `SNYK_JIRA_PRIORITY_FOR_XXX_VULN` env var to override the default an set your value.
> *Example*:
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
        "Description": "\r\n \\*\\*\\*\\* Issue details: \\*\\*\\*\\*\n\r\n cvssScore:  8.10\n exploitMaturity:  proof\\-of\\-concept\n severity:  high\n pkgVersions: 3.0.0\\]\n\r\n*Impacted Paths:*\n\\- \"snyk\"@\"1.228.3\" =\u003e \"proxy\\-agent\"@\"3.1.0\" =\u003e \"pac\\-proxy\\-agent\"@\"3.0.0\" =\u003e \"pac\\-resolver\"@\"3.0.0\"\n\r\n[See this issue on Snyk|https://app.snyk.io/org/test/project/123]\n\n[More About this issue|https://security.snyk.io/vuln/SNYK-JS-PACRESOLVER-1589857]\n\n",
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
        "Description": "\r\n \\*\\*\\*\\* Issue details: \\*\\*\\*\\*\n\r\n cvssScore:  6.30\n exploitMaturity:  proof\\-of\\-concept\n severity:  medium\n pkgVersions: 4.2.0\\]\n\r\n*Impacted Paths:*\n\\- \"snyk\"@\"1.228.3\" =\u003e \"configstore\"@\"3.1.2\" =\u003e \"dot\\-prop\"@\"4.2.0\"\n\r\\- \"snyk\"@\"1.228.3\" =\u003e \"update\\-notifier\"@\"2.5.0\" =\u003e \"configstore\"@\"3.1.2\" =\u003e \"dot\\-prop\"@\"4.2.0\"\n\r\n[See this issue on Snyk|https://app.snyk.io/org/test/project/123]\n\n[More About this issue|https://security.snyk.io/vuln/SNYK-JS-DOTPROP-543499]\n\n",
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
If your jira project has specific required field or custom fields configured, they will need to be added to the config file.
Mandatory fields:
  - Make sure to give both key and value expected by jira under the customMandatoryField key of the config file.
  We support 2 kind of required field: simple key/value pair or nested key/value

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

At the moment we are supporting 3 types of custom Jira fields: [`labels`](https://developer.atlassian.com/server/jira/platform/jira-rest-api-example-create-issue-7897248/), [`MultiGroupPicker`](https://developer.atlassian.com/server/jira/platform/jira-rest-api-example-create-issue-7897248/) and [`MultiSelect`](https://developer.atlassian.com/server/jira/platform/jira-rest-api-example-create-issue-7897248/).

Make sure to respect the format in the config file:
- simpleField:
  ``` "customfield_10601": value: jiraValue-simpleField-something to add to the ticket``` will be sent as ``` "customfield_10601":"something to add to the ticket"```
- labels:
  ``` "customfield_10601": value: jiraValue-label-Value1,Value2``` will be sent as ``` "customfield_10601":["Value1","Value2"]```
- MultiGroupPicker:
  ``` "customfield_10601": value: jiraValue-MultiGroupPicker-Value1,Value2``` will be sent as ``` "customfield_10601":[{"name":"Value1"},{"name":"Value2"}]```
- MultiGroupPicker:
  ``` "customfield_10601": value: jiraValue-MultiSelect-Value1,Value2``` will be sent as ``` "customfield_10601":[{"value":"Value1"},{"value":"Value2"}]```

For more details on jira custom field please visit [Jira documentation](https://developer.atlassian.com/server/jira/platform/jira-rest-api-example-create-issue-7897248/)

```
schema: 1
snyk:
    orgID: a1b2c3de-99b1-4f3f-bfdb-6ee4b4990513 # <SNYK_ORG_ID>
    projectID: a1b2c3de-99b1-4f3f-bfdb-6ee4b4990514 # <SNYK_PROJECT_ID>
    severity: critical # <critical|high|medium|low>
    severityArray: low # <critical,high,medium,low>
    maturityFilter: mature # <mature,proof-of-concept,no-known-exploit,no-data>
    type: all # <all|vuln|license>
    priorityScoreThreshold: 10
    api: https://myapi # <API endpoint> default to
    ifUpgradeAvailableOnly: false # <true|false>
jira:
    jiraTicketType: Task # <Task|Bug|....>
    jiraProjectID: 12345
    assigneeId: 123abc456def789
    priorityIsSeverity: true # <true|false>
    labels: label1 # <IssueLabel1>,<IssueLabel2>
    jiraProjectKey: testProject
    priorityIsSeverity: false # <true|false> (defaults: Low|Medium|High|Critical=>Low|Medium|High|Highest)
    customMandatoryFields:
        key:
            value: 5
        customfield_10601:
          value: jiraValue-MultiGroupPicker-Value1,Value2
        customfield_10602:
          value: jiraValue-simpleField-something to add to the ticket
```

Notes:
  - The token is not expected present in the config file
  - Command line arguments override the config file. IE:
      Using the config file above, running `./snyk-jira-sync-macOs --Org=1234 --configFile=./path/to/folder --token=123`
      the org ID used by the tool will be `1234` and not `a1b2c3de-99b1-4f3f-bfdb-6ee4b4990513`
  - See 'Extended options' for default values
