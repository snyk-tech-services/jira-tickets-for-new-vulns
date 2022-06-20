package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/michael-go/go-jsn/jsn"
)

// JiraIssue represents the top level Struct for Jira issue description
type JiraIssue struct {
	Fields Field `json:"fields"`
}

// Some info on ommit : https://www.sohamkamani.com/golang/omitempty/#values-that-cannot-be-omitted
type PriorityType struct {
	Name string `json:"name,omitempty"`
}

// Field represents a Jira issue basic fields
type Field struct {
	Projects    Project       `json:"project"`
	Summary     string        `json:"summary"`
	Description string        `json:"description"`
	IssueTypes  IssueType     `json:"issuetype"`
	Assignees   *Assignee     `json:"assignee,omitempty"`
	Priority    *PriorityType `json:"priority,omitempty"`
	Labels      []string      `json:"labels,omitempty"`
}

// Assignee is the account ID of the Jira user to assign tickets to
type Assignee struct {
	Name      string `json:"name,omitempty"`
	AccountId string `json:"accountId,omitempty"`
}

// Project is the Jira project ID or Key
type Project struct {
	ID  string `json:"id,omitempty"`
	Key string `json:"key,omitempty"`
}

// IssueType is type of Bug|Epic|Task
type IssueType struct {
	Name string `json:"name"`
}

func getJiraTickets(Mf MandatoryFlags, projectID string, customDebug debug) (map[string]string, error) {
	responseData, err := makeSnykAPIRequest("GET", Mf.endpointAPI+"/v1/org/"+Mf.orgID+"/project/"+projectID+"/jira-issues", Mf.apiToken, nil, customDebug)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not get the Jira issues via Snyk API")
		return nil, errors.New("Could not get the tickets")
	}

	tickets, err := jsn.NewJson(responseData)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not read Jira issues via Snyk API")
		return nil, errors.New("Could not read Jira issues via Snyk API")
	}

	tickRefs := make(map[string]string)

	tickets.IterMap(func(k string, v jsn.Json) bool {
		tickRefs[k] = v.I(0).K("jiraIssue").K("key").String().Value
		return true
	})
	return tickRefs, err
}

/***
function openJiraTicket
argument lots
return responseData: request response from snyk API
return error: if request or ticket creation failure
create a ticket for a specific vuln
	ticket is created and send to snyk jira ticket creation API endpoint
***/
func openJiraTicket(flags flags, projectInfo jsn.Json, vulnForJira interface{}, customDebug debug) ([]byte, *Tickets, error, string) {

	jsonVuln, _ := jsn.NewJson(vulnForJira)
	issueType := jsonVuln.K("data").K("attributes").K("issueType").String().Value
	vulnID := jsonVuln.K("id").String().Value
	var ticketFile *Tickets
	var jiraTicket *JiraIssue

	if issueType == "code" {
		jiraTicket = formatCodeJiraTicket(jsonVuln, projectInfo)
		vulnID = jsonVuln.K("data").K("id").String().Value
	} else {
		jiraTicket = formatJiraTicket(jsonVuln, projectInfo)
	}

	if flags.mandatoryFlags.jiraProjectKey != "" {
		jiraTicket.Fields.Projects.Key = flags.mandatoryFlags.jiraProjectKey
	} else if flags.mandatoryFlags.jiraProjectID != "" {
		jiraTicket.Fields.Projects.ID = flags.mandatoryFlags.jiraProjectID
	}

	jiraTicket.Fields.IssueTypes.Name = flags.optionalFlags.jiraTicketType

	projectInfoId := projectInfo.K("id").String().Value
	var jiraApiUrl = flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/project/"+projectInfoId+"/issue/"+vulnID+"/jira-issue"

	if projectInfoId == "" {
		return nil, nil, errors.New("Failure, Could not retrieve project ID"), jiraApiUrl
	}

	if flags.optionalFlags.labels != "" {
		jiraTicket.Fields.Labels = strings.Split(flags.optionalFlags.labels, ",")
	}

	if flags.optionalFlags.assigneeName != "" {
		var assignee Assignee
		assignee.Name = flags.optionalFlags.assigneeName
		jiraTicket.Fields.Assignees = &assignee
	} else if flags.optionalFlags.assigneeID != "" {
		var assignee Assignee
		assignee.AccountId = flags.optionalFlags.assigneeID
		jiraTicket.Fields.Assignees = &assignee
	}

	if flags.optionalFlags.priorityIsSeverity {
		var priority PriorityType

		severity := jsonVuln.K("issueData").K("severity").String().Value
		if issueType == "code" {
			severity = jsonVuln.K("data").K("attributes").K("severity").String().Value
		}

		jiraMappingEnvVarName := fmt.Sprintf("SNYK_JIRA_PRIORITY_FOR_%s_VULN", strings.ToUpper(severity))
		val, present := os.LookupEnv(jiraMappingEnvVarName)
		if present {
			priority.Name = val
		} else {
			if severity == "critical" {
				priority.Name = "Highest"
			} else {

				priority.Name = strings.Title(severity)

			}

		}
		jiraTicket.Fields.Priority = &priority
	}

	ticket, err := json.Marshal(jiraTicket)
	if err != nil {
		customDebug.Debug("*** ERROR *** Error while creating the ticket")
		return nil, nil, errors.New("Failure, Failure to create ticket(s)"), jiraApiUrl
	}

	// Add Mandatory filed to the ticket
	if len(flags.customMandatoryJiraFields) > 0 {
		ticket = addMandatoryFieldToTicket(ticket, flags.customMandatoryJiraFields, customDebug)
	}

	customDebug.Debugf("*** INFO *** Ticket data to be sent %s", string(ticket))

	// create ticket struct to add in the logfile
	// test is dryRun, if not log only what's have been created
	if flags.optionalFlags.dryRun == true {
		ticketFile = &Tickets{
			Summary:     jiraTicket.Fields.Summary,
			Description: jiraTicket.Fields.Description,
		}
	}

	// check that vulnId exist and dryRun is off
	if len(vulnID) != 0 && !flags.optionalFlags.dryRun {
		var er error
		responseData, er := makeSnykAPIRequest("POST", jiraApiUrl, flags.mandatoryFlags.apiToken, ticket, customDebug)

		if er != nil {
			if er.Error() == "Failed too many time with 50x errors" {
				return nil, nil, errors.New("Failed too many time with 50x errors"), jiraApiUrl
			}
			customDebug.Debug("*** ERROR *** Request failed")
			return nil, nil, errors.New(er.Error()), jiraApiUrl
		}

		if bytes.Equal(responseData, nil) {
			customDebug.Debugf("*** ERROR *** Request response from %s is empty\n", jiraApiUrl)
			return nil, nil, errors.New("Received empty response from /jira-issues API"), jiraApiUrl
		}

		// create ticket struct to add in the json logfile
		// log only what's have been created
		ticketFile = &Tickets{
			Summary:         jiraTicket.Fields.Summary,
			Description:     jiraTicket.Fields.Description,
			JiraIssueDetail: getJiraTicketId(responseData),
		}

		return responseData, ticketFile, nil, jiraApiUrl
	}
	return nil, ticketFile, errors.New("*** ERROR *** Failed to create ticket, vuln ID is empty"), jiraApiUrl
}

func displayErrorForIssue(vulnForJira interface{}, endpointAPI string, error error) string {

	jsonVuln, _ := jsn.NewJson(vulnForJira)
	vulnID := jsonVuln.K("id").String().Value
	log.Printf("*** ERROR *** Request to %s failed.\nERROR: %s", endpointAPI, error)

	return vulnID + "\n"
}

func openJiraTickets(flags flags, projectInfo jsn.Json, vulnsForJira map[string]interface{}, customDebug debug) (int, string, string, map[string]interface{}) {
	fullResponseDataAggregated := ""
	fullListNotCreatedIssue := ""
	RequestFailed := false
	issueCreated := 0
	MaxNumberOfRetry := 1
	var ticketArray []Tickets

	for _, vulnForJira := range vulnsForJira {

		// skip ticket creating if the vuln is not upgradable
		if flags.optionalFlags.ifUpgradeAvailableOnly {
			jsonVuln, _ := jsn.NewJson(vulnForJira)
			if jsonVuln.K("fixInfo").K("isUpgradable").Bool().Value == false {
				continue
			}
		}

		RequestFailed = false

		customDebug.Debug("*** INFO *** Trying to open ticket for vuln:", vulnForJira)
		responseDataAggregatedByte, ticket, err, jiraApiUrl := openJiraTicket(flags, projectInfo, vulnForJira, customDebug)
		if err != nil {
			customDebug.Debugf("*** ERROR *** Opening Jira ticket failed %s\n", jiraApiUrl)
			RequestFailed = true
		}

		// Don't need to do all that on dryRun
		if !flags.optionalFlags.dryRun {

			if RequestFailed == true {
				for numberOfRetries := 0; numberOfRetries < MaxNumberOfRetry; numberOfRetries++ {

					customDebug.Debug("*** INFO *** Retrying with priorityIsSeverity set to false, max retries=", MaxNumberOfRetry)

					flags.optionalFlags.priorityIsSeverity = false
					responseDataAggregatedByte, ticket, err, jiraApiUrl = openJiraTicket(flags, projectInfo, vulnForJira, customDebug)
					if err != nil {
						fullListNotCreatedIssue += displayErrorForIssue(vulnForJira, jiraApiUrl, err)
					} else {
						RequestFailed = false
						break
					}
				}
			}
			if RequestFailed == true && strings.Contains(strings.ToLower(string(responseDataAggregatedByte)), "error") {
				fullListNotCreatedIssue += displayErrorForIssue(vulnForJira, jiraApiUrl, err)
				continue
			}

			if responseDataAggregatedByte != nil {
				// increment the number of ticket created adn response
				fullResponseDataAggregated += "\n" + string(responseDataAggregatedByte) + "\n"
				issueCreated += 1
			}
		}

		// add only existing ticket to the array
		if ticket != nil {
			ticketArray = append(ticketArray, *ticket)
		}
	}

	// getting project ID and associate the ticket list to it
	projectIdString := projectInfo.K("id").String().Value

	project := make(map[string]interface{})
	project[projectIdString] = ticketArray

	if fullResponseDataAggregated == "" && !flags.optionalFlags.dryRun {
		customDebug.Debugf("*** ERROR *** Request response from %s is empty\n", flags.mandatoryFlags.endpointAPI)
	}

	customDebug.Debugf("*** INFO *** %d issueCreated, fullResponseDataAggregated: %s", issueCreated, fullResponseDataAggregated)

	return issueCreated, fullResponseDataAggregated, fullListNotCreatedIssue, project
}
