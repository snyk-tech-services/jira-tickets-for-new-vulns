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

// JiraIssue represents the top level Struct for JIRA issue description
type JiraIssue struct {
	Fields Field `json:"fields"`
}

// Some info on ommit : https://www.sohamkamani.com/golang/omitempty/#values-that-cannot-be-omitted
type PriorityType struct {
	Name string `json:"name,omitempty"`
}

// Field represents a JIRA issue basic fields
type Field struct {
	Projects    Project       `json:"project"`
	Summary     string        `json:"summary"`
	Description string        `json:"description"`
	IssueTypes  IssueType     `json:"issuetype"`
	Assignees   *Assignee     `json:"assignee,omitempty"`
	Priority    *PriorityType `json:"priority,omitempty"`
	Labels      []string      `json:"labels,omitempty"`
}

// Assignee is the account ID of the JIRA user to assign tickets to
type Assignee struct {
	Name      string `json:"name,omitempty"`
	AccountId string `json:"accountId,omitempty"`
}

// Project is the JIRA project ID or Key
type Project struct {
	ID  string `json:"id,omitempty"`
	Key string `json:"key,omitempty"`
}

// IssueType is type of Bug|Epic|Task
type IssueType struct {
	Name string `json:"name"`
}

func getJiraTickets(Mf MandatoryFlags, projectID string, customDebug debug) map[string]string {
	responseData, err := makeSnykAPIRequest("GET", Mf.endpointAPI+"/v1/org/"+Mf.orgID+"/project/"+projectID+"/jira-issues", Mf.apiToken, nil, customDebug)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not get the tickets")
		return nil
	}

	tickets, err := jsn.NewJson(responseData)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not read the tickets")
		return nil
	}

	tickRefs := make(map[string]string)

	tickets.IterMap(func(k string, v jsn.Json) bool {
		tickRefs[k] = v.I(0).K("jiraIssue").K("key").String().Value
		return true
	})
	return tickRefs
}

/***
function openJiraTicket
argument lots
return responseData: request response from snyk API
return error: if request or ticket creation failure
create a ticket for a specific vuln
	ticket is created and send to snyk jira ticket creation API endpoint
***/
func openJiraTicket(flags flags, projectInfo jsn.Json, vulnForJira interface{}, customDebug debug) ([]byte, *Tickets, error) {

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

	if projectInfoId == "" {
		return nil, nil, errors.New("Failure, Could not retrieve project ID")
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
		return nil, nil, errors.New("Failure, Failure to create ticket(s)")
	}

	// Add Mandatory filed to the ticket
	if len(flags.customMandatoryJiraFields) > 0 {
		ticket = addMandatoryFieldToTicket(ticket, flags.customMandatoryJiraFields, customDebug)
	}

	customDebug.Debugf("*** INFO *** Ticket to be send %s", string(ticket))

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
		responseData, er := makeSnykAPIRequest("POST", flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/project/"+projectInfoId+"/issue/"+vulnID+"/jira-issue", flags.mandatoryFlags.apiToken, ticket, customDebug)

		if er != nil {
			customDebug.Debug("*** ERROR *** Request failed")
			return nil, nil, errors.New("Failure, Failure to create ticket(s)")
		}

		if bytes.Equal(responseData, nil) {
			customDebug.Debugf("*** ERROR *** Request response from %s is empty\n", flags.mandatoryFlags.endpointAPI)
			return nil, nil, errors.New("Failure, Failure to create ticket(s)")
		}

		// create ticket struct to add in the json logfile
		// log only what's have been created
		ticketFile = &Tickets{
			Summary:         jiraTicket.Fields.Summary,
			Description:     jiraTicket.Fields.Description,
			JiraIssueDetail: getJiraTicketId(responseData),
		}

		return responseData, ticketFile, nil
	}
	return nil, ticketFile, errors.New("*** ERROR *** Failure to create ticket, vuln ID is empty")
}

func displayErrorForIssue(vulnForJira interface{}, endpointAPI string, customDebug debug) string {

	jsonVuln, _ := jsn.NewJson(vulnForJira)
	vulnID := jsonVuln.K("id").String().Value
	customDebug.Debugf("*** ERROR *** Request to %s failed too many time\n Ticket cannot be created for this issue: %s\n", endpointAPI, vulnID)

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

		customDebug.Debug("*** INFO *** Trying to open ticket for vuln", vulnForJira)

		responseDataAggregatedByte, ticket, err := openJiraTicket(flags, projectInfo, vulnForJira, customDebug)
		if err != nil {
			customDebug.Debugf("*** ERROR *** opening jira ticket failed endpoint %s\n", flags.mandatoryFlags.endpointAPI)
			RequestFailed = true
		}

		// Don't need to do all that on dryRun
		if !flags.optionalFlags.dryRun {

			if RequestFailed == true {
				for numberOfRetries := 0; numberOfRetries < MaxNumberOfRetry; numberOfRetries++ {

					customDebug.Debug("*** INFO *** Retrying with priorityIsSeverity set to false, max retry ", MaxNumberOfRetry)

					flags.optionalFlags.priorityIsSeverity = false
					responseDataAggregatedByte, ticket, err = openJiraTicket(flags, projectInfo, vulnForJira, customDebug)
					if err != nil {
						fullListNotCreatedIssue += displayErrorForIssue(vulnForJira, flags.mandatoryFlags.endpointAPI, customDebug)
					} else {
						RequestFailed = false
						break
					}
				}
			}
			if RequestFailed == true && strings.Contains(strings.ToLower(string(responseDataAggregatedByte)), "error") {
				fullListNotCreatedIssue += displayErrorForIssue(vulnForJira, flags.mandatoryFlags.endpointAPI, customDebug)
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
		log.Printf("*** ERROR *** Request response from %s is empty\n", flags.mandatoryFlags.endpointAPI)
	}

	customDebug.Debugf("*** INFO *** %d issueCreated, fullResponseDataAggregated: %s", issueCreated, fullResponseDataAggregated)

	return issueCreated, fullResponseDataAggregated, fullListNotCreatedIssue, project
}
