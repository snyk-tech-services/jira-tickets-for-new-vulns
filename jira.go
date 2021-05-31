package main

import (
	"encoding/json"
	"log"

	"github.com/michael-go/go-jsn/jsn"
)

// JiraIssue represents the top level Struct for JIRA issue description
type JiraIssue struct {
	Fields Field `json:"fields"`
}

// Field represents a JIRA issue basic fields
type Field struct {
	Projects    Project   `json:"project"`
	Summary     string    `json:"summary"`
	Description string    `json:"description"`
	IssueTypes  IssueType `json:"issuetype"`
	Assignees	Assignee  `json:"assignee"`
}

// Assignee is the account ID of the JIRA user to assign tickets to
type Assignee struct {
	ID string `json:"accountId,omitempty"`
}

// Project is the JIRA project ID
type Project struct {
	ID string `json:"id"`
}

// IssueType is type of Bug|Epic|Task
type IssueType struct {
	Name string `json:"name"`
}

func getJiraTickets(endpointAPI string, orgID string, projectID string, token string) map[string]string {
	responseData := makeSnykAPIRequest("GET", endpointAPI+"/v1/org/"+orgID+"/project/"+projectID+"/jira-issues", token, nil)

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

func openJiraTickets(endpointAPI string, orgID string, token string, jiraProjectID string, jiraTicketType string, assigneeID string, projectInfo jsn.Json, vulnsForJira map[string]interface{}) string {
	responseDataAggregated := ""
	for _, vulnForJira := range vulnsForJira {

		jsonVuln, _ := jsn.NewJson(vulnForJira)
		vulnID := jsonVuln.K("id").String().Value
		jiraTicket := formatJiraTicket(jsonVuln, projectInfo)

		jiraTicket.Fields.Projects.ID = jiraProjectID
		jiraTicket.Fields.IssueTypes.Name = jiraTicketType
		jiraTicket.Fields.Assignees.ID = assigneeID

		ticket, err := json.Marshal(jiraTicket)
		if err != nil {
			log.Fatalln(err)
		}

		responseData := makeSnykAPIRequest("POST", endpointAPI+"/v1/org/"+orgID+"/project/"+projectInfo.K("id").String().Value+"/issue/"+vulnID+"/jira-issue", token, ticket)
		responseDataAggregated += "\n" + string(responseData)
	}
	return responseDataAggregated
}
