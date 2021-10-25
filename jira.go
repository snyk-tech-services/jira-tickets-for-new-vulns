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

func getJiraTickets(endpointAPI string, orgID string, projectID string, token string) map[string]string {

	responseData, err := makeSnykAPIRequest("GET", endpointAPI+"/v1/org/"+orgID+"/project/"+projectID+"/jira-issues", token, nil)
	if err != nil {
		fmt.Println("Could not get the tickets")
		log.Fatal(err)
	}

	tickets, err := jsn.NewJson(responseData)
	if err != nil {
		log.Fatal(err)
	}

	tickRefs := make(map[string]string)

	tickets.IterMap(func(k string, v jsn.Json) bool {
		tickRefs[k] = v.I(0).K("jiraIssue").K("key").String().Value
		return true
	})
	return tickRefs
}

func openJiraTicket(endpointAPI string, orgID string, token string, jiraProjectID string, jiraProjectKey string, jiraTicketType string, assigneeName string, assigneeID string, labels string, projectInfo jsn.Json, vulnForJira interface{}, priorityIsSeverity bool) ([]byte, error) {

	jsonVuln, _ := jsn.NewJson(vulnForJira)
	vulnID := jsonVuln.K("id").String().Value

	jiraTicket := formatJiraTicket(jsonVuln, projectInfo)

	if jiraProjectKey != "" {
		jiraTicket.Fields.Projects.Key = jiraProjectKey
	} else if jiraProjectID != "" {
		jiraTicket.Fields.Projects.ID = jiraProjectID
	}

	jiraTicket.Fields.IssueTypes.Name = jiraTicketType

	projectInfoId := projectInfo.K("id").String().Value

	if projectInfoId == "" {
		return nil, errors.New("Failure, Could not retrieve project ID")
	}

	if labels != "" {
		jiraTicket.Fields.Labels = strings.Split(labels, ",")
	}

	if assigneeName != "" {
		var assignee Assignee
		assignee.Name = assigneeName
		jiraTicket.Fields.Assignees = &assignee
	} else if assigneeID != "" {
		var assignee Assignee
		assignee.AccountId = assigneeID
		jiraTicket.Fields.Assignees = &assignee
	}

	if priorityIsSeverity {
		var priority PriorityType
		jiraMappingEnvVarName := fmt.Sprintf("SNYK_JIRA_PRIORITY_FOR_%s_VULN", strings.ToUpper(jsonVuln.K("issueData").K("severity").String().Value))
		val, present := os.LookupEnv(jiraMappingEnvVarName)
		if present {
			priority.Name = val
		} else {
			if jsonVuln.K("issueData").K("severity").String().Value == "critical" {
				priority.Name = "Highest"
			} else {

				priority.Name = strings.Title(jsonVuln.K("issueData").K("severity").String().Value)

			}

		}
		jiraTicket.Fields.Priority = &priority
	}

	ticket, err := json.Marshal(jiraTicket)
	if err != nil {
		fmt.Println("Error while creating the ticket")
		return nil, errors.New("Failure, Failure to create ticket(s)")
	}

	// TODO: this needs to be a debug
	//fmt.Println("ticket to be send: ", string(ticket))

	if len(vulnID) != 0 {
		var er error
		responseData, er := makeSnykAPIRequest("POST", endpointAPI+"/v1/org/"+orgID+"/project/"+projectInfoId+"/issue/"+vulnID+"/jira-issue", token, ticket)

		if er != nil {
			fmt.Println("Request failed")
			return nil, errors.New("Failure, Failure to create ticket(s)")
		}

		if bytes.Equal(responseData, nil) {
			fmt.Printf("Request response from %s is empty\n", endpointAPI)
			return nil, errors.New("Failure, Failure to create ticket(s)")
		}
		return responseData, nil
	}
	return nil, errors.New("Failure to create ticket, vuln ID is empty")
}

func displayErrorForIssue(vulnForJira interface{}, endpointAPI string) string {

	jsonVuln, _ := jsn.NewJson(vulnForJira)
	vulnID := jsonVuln.K("id").String().Value
	fmt.Printf("Request to %s failed too many time\n Ticket cannot be created for this issue: %s\n", endpointAPI, vulnID)
	return vulnID + "\n"
}

func openJiraTickets(endpointAPI string, orgID string, token string, jiraProjectID string, jiraProjectKey string, jiraTicketType string, assigneeName string, assigneeID string, labels string, projectInfo jsn.Json, vulnsForJira map[string]interface{}, priorityIsSeverity bool) (int, string, string) {
	fullResponseDataAggregated := ""
	fullListNotCreatedIssue := ""
	RequestFailed := false
	issueCreated := 0
	MaxNumberOfRetry := 1

	for _, vulnForJira := range vulnsForJira {
		RequestFailed = false
		responseDataAggregatedByte, err := openJiraTicket(endpointAPI, orgID, token, jiraProjectID, jiraProjectKey, jiraTicketType, assigneeName, assigneeID, labels, projectInfo, vulnForJira, priorityIsSeverity)

		if err != nil {
			fmt.Printf("Request to %s failed\n", endpointAPI)
			RequestFailed = true
		}

		if RequestFailed == true {
			for numberOfRetries := 0; numberOfRetries < MaxNumberOfRetry; numberOfRetries++ {
				fmt.Println("Retrying with priorityIsSeverity set to false, max retry ", MaxNumberOfRetry)
				priorityIsSeverity = false
				responseDataAggregatedByte, err = openJiraTicket(endpointAPI, orgID, token, jiraProjectID, jiraProjectKey, jiraTicketType, assigneeName, assigneeID, labels, projectInfo, vulnForJira, priorityIsSeverity)
				if err != nil {
					fullListNotCreatedIssue += displayErrorForIssue(vulnForJira, endpointAPI)
				} else {
					RequestFailed = false
					break
				}
			}
		}
		if RequestFailed == true && strings.Contains(strings.ToLower(string(responseDataAggregatedByte)), "error") {
			fullListNotCreatedIssue += displayErrorForIssue(vulnForJira, endpointAPI)
			continue
		}

		if responseDataAggregatedByte != nil {
			fullResponseDataAggregated += "\n" + string(responseDataAggregatedByte) + "\n"
			issueCreated += 1
		}
	}

	if fullResponseDataAggregated == "" {
		fmt.Printf("Request response from %s is empty\n", endpointAPI)
	}

	return issueCreated, fullResponseDataAggregated, fullListNotCreatedIssue
}
