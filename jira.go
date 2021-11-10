package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
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

/***
function AddToTicketFile
input ticket to send []byte
input projectId to which the issue is linked []byte
return void
Add the created ticket to a text file
	if file doesn't exist =>
		- create it
		- check if the project id is already in the file, if not => new project => add it
		- add the list of ticket
	else => add new ticket at the end of the file
File name set by default to listOfTicketCreated_date.log
***/
func AddToTicketFile(ticket []byte, projectId []byte) {

	// Get date
	date := getDate()

	// Set filename
	filename := "listOfTicketCreated_" + date + ".log"

	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// todo add better debug
		// Do not fail the tool if file cannot be created print a warning instead
		log.Printf(err.Error())
	}

	// find root path
	_, b, _, _ := runtime.Caller(1)
	var d []string
	d = append(d, path.Join(path.Dir(b)))
	filenamePathArray := append(d, filename)
	// find os separator
	separator := string(os.PathSeparator)
	// build filename path
	filenamePath := strings.Join(filenamePathArray, separator)

	// Add project ID if needed
	projectIdString := fmt.Sprintf(" ***** list of ticket for project %s ***** ", string(projectId))
	projectIdFound, err := findProjectId(projectIdString, filenamePath)
	if err != nil {
		log.Println("could not open file")
		return
	}
	projectIdString = "\n" + projectIdString + "\n"

	if !projectIdFound {
		// This append the project ID string the beginning of the ticket
		ticket = append([]byte(projectIdString), ticket...)
	}

	// Add ticket
	_, err = f.Write(ticket)
	_, err = f.Write([]byte("\n"))
	if err != nil {
		// todo add better debug
		// Do not fail the tool if file cannot be created print a warning instead
		log.Printf(err.Error())
	}

	f.Close()

	return
}

/***
function openJiraTicket
argument lots
return responseData: request response from snyk API
return error: if request or ticket creation failure
create a ticket for a specific vuln
	ticket is created and send to snyk jira ticket creation API endpoint
***/
func openJiraTicket(endpointAPI string, orgID string, token string, jiraProjectID string, jiraProjectKey string, jiraTicketType string, assigneeName string, assigneeID string, labels string, projectInfo jsn.Json, vulnForJira interface{}, priorityIsSeverity bool, dryRun bool) ([]byte, error) {

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

	// Add ticket to the ticketCreated.log file
	// test is dryRun, if not log only what's have been created
	if dryRun {
		AddToTicketFile(ticket, []byte(projectInfoId))
	}

	// check that vulnId exist and dryRun is off
	if len(vulnID) != 0 && !dryRun {
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

		// Add ticket to the ticketCreated.log file
		// log only what's have been created
		AddToTicketFile(ticket, []byte(projectInfoId))

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

func openJiraTickets(endpointAPI string, orgID string, token string, jiraProjectID string, jiraProjectKey string, jiraTicketType string, assigneeName string, assigneeID string, labels string, projectInfo jsn.Json, vulnsForJira map[string]interface{}, priorityIsSeverity bool, dryRun bool) (int, string, string) {
	fullResponseDataAggregated := ""
	fullListNotCreatedIssue := ""
	RequestFailed := false
	issueCreated := 0
	MaxNumberOfRetry := 1

	for _, vulnForJira := range vulnsForJira {
		RequestFailed = false
		responseDataAggregatedByte, err := openJiraTicket(endpointAPI, orgID, token, jiraProjectID, jiraProjectKey, jiraTicketType, assigneeName, assigneeID, labels, projectInfo, vulnForJira, priorityIsSeverity, dryRun)

		// Don't need to do all that on dryRun
		if !dryRun {
			if err != nil {
				fmt.Printf("Request to %s failed\n", endpointAPI)
				RequestFailed = true
			}

			if RequestFailed == true {
				for numberOfRetries := 0; numberOfRetries < MaxNumberOfRetry; numberOfRetries++ {
					fmt.Println("Retrying with priorityIsSeverity set to false, max retry ", MaxNumberOfRetry)
					priorityIsSeverity = false
					responseDataAggregatedByte, err = openJiraTicket(endpointAPI, orgID, token, jiraProjectID, jiraProjectKey, jiraTicketType, assigneeName, assigneeID, labels, projectInfo, vulnForJira, priorityIsSeverity, dryRun)
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
	}

	// fullResponseDataAggregated will be empty on dryRun
	if fullResponseDataAggregated == "" && !dryRun {
		fmt.Printf("Request response from %s is empty\n", endpointAPI)
	}

	return issueCreated, fullResponseDataAggregated, fullListNotCreatedIssue
}
