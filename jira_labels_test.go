package main

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/michael-go/go-jsn/jsn"

	"github.com/nsf/jsondiff"
	"github.com/stretchr/testify/assert"
)

// Test GetJiraTicket function
func TestGetJiraTicketFunc(t *testing.T) {
	expectedTestURL := "/v1/org/123/project/123/jira-issues"
	assert := assert.New(t)
	server := HTTPResponseCheckAndStub(expectedTestURL, "existingJiraTickets")

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectKey = ""

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	response, _ := getJiraTickets(Mf, "123", cD)

	opts := jsondiff.DefaultConsoleOptions()
	marshalledResp, _ := json.Marshal(response)
	comparison, _ := jsondiff.Compare(readFixture("./fixtures/results/ticketRefs.json"), marshalledResp, &opts)
	assert.Equal("FullMatch", comparison.String())

	return
}

// Test openJiraTickets function
func TestOpenJiraTicketWithLabelsFunc(t *testing.T) {
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
	Of.debug = true
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.labels = "Label1,Label2"
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.cveInTitle = false
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

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

	assert.Equal(NotCreatedIssueId, "")
	fmt.Println(numberIssueCreated)
	assert.NotNil(tickets)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketWithLabels.json")), string(mirroredResponse.Body))

	return
}

func TestOpenJiraTicketWithoutLabelsFunc(t *testing.T) {
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
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.cveInTitle = false
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

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

	assert.Equal(NotCreatedIssueId, "")
	fmt.Println(numberIssueCreated)
	assert.NotNil(tickets)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketWithoutLabels.json")), string(mirroredResponse.Body))

	return
}
