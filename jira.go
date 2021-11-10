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

func getJiraTickets(Mf MandatoryFlags, projectID string, customDebug debug) map[string]string {
	responseData, err := makeSnykAPIRequest("GET", Mf.endpointAPI+"/v1/org/"+Mf.orgID+"/project/"+projectID+"/jira-issues", Mf.apiToken, nil, customDebug)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not get the tickets")
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
func AddToTicketFile(ticket []byte, projectId []byte, customDebug debug) {

	// Get date
	date := getDate()

	// Set filename
	filename := "listOfTicketCreated_" + date + ".log"

	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Do not fail the tool if file cannot be created print a warning instead
		customDebug.Debug("*** ERROR *** Could not create log file")
		customDebug.Debug(err.Error())
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
	projectIdFound, err := findProjectId(projectIdString, filenamePath, customDebug)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not open file")
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
		// Do not fail the tool if file cannot be created print a warning instead
		customDebug.Debug("*** ERROR *** Could not write into log file")
		customDebug.Debug(err.Error())
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
func openJiraTicket(flags flags, projectInfo jsn.Json, vulnForJira interface{}, customDebug debug) ([]byte, error) {

	jsonVuln, _ := jsn.NewJson(vulnForJira)
	vulnID := jsonVuln.K("id").String().Value

	jiraTicket := formatJiraTicket(jsonVuln, projectInfo)

	if flags.mandatoryFlags.jiraProjectKey != "" {
		jiraTicket.Fields.Projects.Key = flags.mandatoryFlags.jiraProjectKey
	} else if flags.mandatoryFlags.jiraProjectID != "" {
		jiraTicket.Fields.Projects.ID = flags.mandatoryFlags.jiraProjectID
	}

	jiraTicket.Fields.IssueTypes.Name = flags.optionalFlags.jiraTicketType

	projectInfoId := projectInfo.K("id").String().Value

	if projectInfoId == "" {
		return nil, errors.New("Failure, Could not retrieve project ID")
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
		customDebug.Debug("*** ERROR *** Error while creating the ticket")
		return nil, errors.New("Failure, Failure to create ticket(s)")
	}

	customDebug.Debugf("*** INFO *** Ticket to be send %s", string(ticket))

	// Add ticket to the ticketCreated.log file
	// test is dryRun, if not log only what's have been created
	if flags.optionalFlags.dryRun == true {
		AddToTicketFile(ticket, []byte(projectInfoId), customDebug)
	}

	// check that vulnId exist and dryRun is off
	if len(vulnID) != 0 && !flags.optionalFlags.dryRun {
		var er error
		responseData, er := makeSnykAPIRequest("POST", flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/project/"+projectInfoId+"/issue/"+vulnID+"/jira-issue", flags.mandatoryFlags.apiToken, ticket, customDebug)

		if er != nil {
			customDebug.Debug("*** ERROR *** Request failed")
			return nil, errors.New("Failure, Failure to create ticket(s)")
		}

		if bytes.Equal(responseData, nil) {
			customDebug.Debugf("*** ERROR *** Request response from %s is empty\n", flags.mandatoryFlags.endpointAPI)
			return nil, errors.New("Failure, Failure to create ticket(s)")
		}

		// Add ticket to the ticketCreated.log file
		// log only what's have been created
		AddToTicketFile(ticket, []byte(projectInfoId), customDebug)

		return responseData, nil
	}
	return nil, errors.New("*** ERROR *** Failure to create ticket, vuln ID is empty")
}

func displayErrorForIssue(vulnForJira interface{}, endpointAPI string, customDebug debug) string {

	jsonVuln, _ := jsn.NewJson(vulnForJira)
	vulnID := jsonVuln.K("id").String().Value
	customDebug.Debugf("*** ERROR *** Request to %s failed too many time\n Ticket cannot be created for this issue: %s\n", endpointAPI, vulnID)

	return vulnID + "\n"
}

func openJiraTickets(flags flags, projectInfo jsn.Json, vulnsForJira map[string]interface{}, customDebug debug) (int, string, string) {
	fullResponseDataAggregated := ""
	fullListNotCreatedIssue := ""
	RequestFailed := false
	issueCreated := 0
	MaxNumberOfRetry := 1

	for _, vulnForJira := range vulnsForJira {

		RequestFailed = false

		customDebug.Debug("*** INFO *** Trying to open ticket for vuln", vulnForJira)

		responseDataAggregatedByte, err := openJiraTicket(flags, projectInfo, vulnForJira, customDebug)
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
					responseDataAggregatedByte, err = openJiraTicket(flags, projectInfo, vulnForJira, customDebug)
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
				fullResponseDataAggregated += "\n" + string(responseDataAggregatedByte) + "\n"
				issueCreated += 1
			}
		}
	}

	if fullResponseDataAggregated == "" && !flags.optionalFlags.dryRun {
		log.Printf("*** ERROR *** Request response from %s is empty\n", flags.mandatoryFlags.endpointAPI)
	}

	customDebug.Debugf("*** INFO *** %d issueCreated, fullResponseDataAggregated: %s", issueCreated, fullResponseDataAggregated)

	return issueCreated, fullResponseDataAggregated, fullListNotCreatedIssue
}
