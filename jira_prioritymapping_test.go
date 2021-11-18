package main

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/michael-go/go-jsn/jsn"

	"github.com/stretchr/testify/assert"
)

// Test openJiraTickets function
func TestOpenJiraTicketWithPriorityMappingFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseStubAndMirrorRequest("/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue", "", "")

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnForJiraAggregatedWithPath.json"), &vulnsForJira)
	if err != nil {
		panic(err)
	}

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	Of.severity = ""
	Of.priorityScoreThreshold = 0
	Of.issueType = ""
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}

	fmt.Println(numberIssueCreated)
	assert.NotNil(tickets)
	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketWithPriorityMapping.json")), string(mirroredResponse.Body))

	return
}

func TestOpenJiraTicketWithoutPriorityMappingFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseStubAndMirrorRequest("/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue", "", "")

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnForJiraAggregatedWithPath.json"), &vulnsForJira)
	if err != nil {
		panic(err)
	}

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	Of.severity = ""
	Of.priorityScoreThreshold = 0
	Of.issueType = ""
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	//endpointAPI string, orgID string, token string, jiraProjectID string, jiraProjectKey string, jiraTicketType string, assigneeName string, assigneeID string, labels string, projectInfo jsn.Json, vulnForJira interface{}, priorityIsSeverity bool
	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}

	fmt.Println(numberIssueCreated)
	assert.NotNil(tickets)
	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketWithoutLabels.json")), string(mirroredResponse.Body))

	return
}

func TestOpenJiraTicketWithCustomPriorityMappingFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseStubAndMirrorRequest("/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue", "", "")

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnForJiraAggregatedWithPath.json"), &vulnsForJira)
	if err != nil {
		panic(err)
	}
	os.Setenv("SNYK_JIRA_PRIORITY_FOR_MEDIUM_VULN", "not too bad")

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	Of.severity = ""
	Of.priorityScoreThreshold = 0
	Of.issueType = ""
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	//endpointAPI string, orgID string, token string, jiraProjectID string, jiraProjectKey string, jiraTicketType string, assigneeName string, assigneeID string, labels string, projectInfo jsn.Json, vulnForJira interface{}, priorityIsSeverity bool
	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}

	assert.NotNil(tickets)
	fmt.Println(numberIssueCreated)
	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketWithCustomPriorityMapping.json")), string(mirroredResponse.Body))

	return
}
