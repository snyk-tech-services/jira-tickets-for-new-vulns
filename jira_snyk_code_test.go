package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/michael-go/go-jsn/jsn"
	"github.com/stretchr/testify/assert"
)

// Test openJiraTickets function
func TestFormatCodeTicketFunc(t *testing.T) {

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	data, _ := jsn.NewJson(readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueAllDetailsForJiraForTicketTest.json"))

	jiraTicket := formatCodeJiraTicket(data, projectInfo)

	// Convert jira ticket into a string
	ticket := fmt.Sprintf("%v", jiraTicket)

	file, err := os.Open("./fixtures/snyk_code_fixtures/results/ticket.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		compare := strings.Contains(ticket, scanner.Text())
		assert.Equal(t, compare, true)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func TestOpenJiraTicketCodeOnly(t *testing.T) {

	server := HTTPResponseCodeIssueStubAndMirrorRequest()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/snyk_code_fixtures/codeProject.json"))
	codeIssueForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueAllDetailsForJiraForTicketTest.json"), &codeIssueForJira)
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
	Of.severityThreshold = ""
	Of.priorityScoreThreshold = 0
	Of.issueType = ""
	Of.debug = true
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

	responseDataAggregatedByte, ticket, err, jiraApiUrl := openJiraTicket(flags, projectInfo, codeIssueForJira, cD)

	assert.NotNil(t, ticket)
	assert.NotNil(t, jiraApiUrl)
	assert.NotNil(t, responseDataAggregatedByte)

}

func TestOpenJiraTicketCodeOnlyWithLabel(t *testing.T) {

	assert := assert.New(t)
	server := HTTPResponseStubAndMirrorCodeRequest()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/snyk_code_fixtures/codeProject.json"))
	codeIssueForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueAllDetailsForJira.json"), &codeIssueForJira)
	if err != nil {
		panic(err)
	}

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "456"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	Of.severityThreshold = ""
	Of.priorityScoreThreshold = 0
	Of.issueType = ""
	Of.debug = true
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.assigneeName = ""
	Of.labels = "Label1,Label2"
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

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, codeIssueForJira, cD)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}

	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(1, numberIssueCreated)
	assert.NotNil(tickets)
	assert.Equal(string(readFixture("./fixtures/snyk_code_fixtures/results/codeTicketWithLabels.json")), string(mirroredResponse.Body))

	return
}

func TestOpenJiraTicketCodeOnlyWithSeverity(t *testing.T) {

	assert := assert.New(t)
	server := HTTPResponseStubAndMirrorCodeRequest()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/snyk_code_fixtures/codeProject.json"))
	codeIssueForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/snyk_code_fixtures/codeIssueForJira.json"), &codeIssueForJira)
	if err != nil {
		panic(err)
	}

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "456"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	Of.severityThreshold = ""
	Of.priorityScoreThreshold = 0
	Of.issueType = ""
	Of.debug = true
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

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, codeIssueForJira, cD)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}

	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(numberIssueCreated, 1)
	assert.NotNil(tickets)
	assert.Equal(string(readFixture("./fixtures/snyk_code_fixtures/results/codeTicketWithSeverity.json")), string(mirroredResponse.Body))

	return
}

func TestOpenJiraTicketCodeOnlyWithAssigneeId(t *testing.T) {

	assert := assert.New(t)
	server := HTTPResponseStubAndMirrorCodeRequest()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/snyk_code_fixtures/codeProject.json"))
	codeIssueForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/snyk_code_fixtures/codeIssueForJira.json"), &codeIssueForJira)
	if err != nil {
		panic(err)
	}

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "456"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	Of.severityThreshold = ""
	Of.priorityScoreThreshold = 0
	Of.issueType = ""
	Of.debug = true
	Of.jiraTicketType = "Bug"
	Of.assigneeID = "123456"
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

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, codeIssueForJira, cD)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}

	assert.Equal(NotCreatedIssueId, "")
	fmt.Println(numberIssueCreated)
	assert.NotNil(tickets)
	assert.Equal(string(readFixture("./fixtures/snyk_code_fixtures/results/codeTicketWithAssigneeId.json")), string(mirroredResponse.Body))

	return
}

func TestOpenJiraTicketCodeOnlyWithAssigneeName(t *testing.T) {

	assert := assert.New(t)
	server := HTTPResponseStubAndMirrorCodeRequest()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/snyk_code_fixtures/codeProject.json"))
	codeIssueForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/snyk_code_fixtures/codeIssueForJira.json"), &codeIssueForJira)
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
	Of.severityThreshold = ""
	Of.priorityScoreThreshold = 0
	Of.issueType = ""
	Of.debug = true
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.assigneeName = "test"
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

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, codeIssueForJira, cD)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}

	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(numberIssueCreated, 1)
	assert.NotNil(tickets)
	assert.Equal(string(readFixture("./fixtures/snyk_code_fixtures/results/codeTicketWithAssigneeName.json")), string(mirroredResponse.Body))

	return
}

func TestGetSnykCodeIssueWithoutTickets(t *testing.T) {

	os.Setenv("EXECUTION_ENVIRONMENT", "test")

	assert := assert.New(t)

	server := HTTPResponseCodeIssueStubAndMirrorRequest()

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	// Of.severity = "low,high,medium,critical"
	Of.severityThreshold = "low"
	Of.priorityScoreThreshold = 0
	Of.issueType = "all"
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.ifUpgradeAvailableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	var tickets map[string]string
	tickets = make(map[string]string)
	// Simulate an existing ticket for that vuln
	tickets["xxbac5ed-83dd-xx65-8730-2xxx4467e0xx"] = "FPI-454"

	response, _ := getSnykCodeIssueWithoutTickets(flags, "789", tickets, cD)
	assert.Equal(2, len(response))

	return

}

func TestGetSnykCodeIssueWithoutTicketsWithMultipleSeverityFilter(t *testing.T) {

	os.Setenv("EXECUTION_ENVIRONMENT", "test")

	assert := assert.New(t)

	server := HTTPResponseCodeIssueStubAndMirrorRequest()

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	Of.severities = "high,medium"
	Of.priorityScoreThreshold = 0
	Of.issueType = "all"
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.ifUpgradeAvailableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	var tickets map[string]string
	tickets = make(map[string]string)
	// Simulate an existing ticket for that vuln
	tickets["xxbac5ed-83dd-xx65-8730-2xxx4467e0xx"] = "FPI-454"

	response := getSnykCodeIssueWithoutTickets(flags, "789", tickets, cD)
	assert.Equal(1, len(response))

	return

}

func TestGetSnykCodeIssueWithoutTicketsWithSeverityFilter(t *testing.T) {

	os.Setenv("EXECUTION_ENVIRONMENT", "test")

	assert := assert.New(t)

	server := HTTPResponseCodeIssueStubAndMirrorRequest()

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	Of.severityThreshold = "high"
	Of.priorityScoreThreshold = 0
	Of.issueType = "all"
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.ifUpgradeAvailableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	var tickets map[string]string
	tickets = make(map[string]string)
	// Simulate an existing ticket for that vuln
	tickets["xxbac5ed-83dd-xx65-8730-2xxx4467e0xx"] = "FPI-454"

	response, _ := getSnykCodeIssueWithoutTickets(flags, "789", tickets, cD)
	assert.Equal(1, len(response))

	return
}

func TestGetSnykCodeIssueWithoutTicketsWithPagination(t *testing.T) {

	os.Setenv("EXECUTION_ENVIRONMENT", "test")

	assert := assert.New(t)

	server := HTTPResponseCodeIssueStubAndMirrorRequest()

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	// Of.severity = "low,high,medium,critical"
	Of.severityThreshold = "low"
	Of.priorityScoreThreshold = 0
	Of.issueType = "all"
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.ifUpgradeAvailableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	var tickets map[string]string
	tickets = make(map[string]string)
	// Simulate an existing ticket for that vuln
	tickets["xxbac5ed-83dd-xx65-8730-2xxx4467e0xx"] = "FPI-454"

	response, _ := getSnykCodeIssueWithoutTickets(flags, "1234", tickets, cD)

	assert.Equal(2, len(response))

	return

}
