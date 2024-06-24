package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/michael-go/go-jsn/jsn"

	"github.com/stretchr/testify/assert"
)

// Test openJiraTickets function
func TestOpenJiraTicketFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraTickets("/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue")

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnsForJira.json"), &vulnsForJira)
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
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.Equal("", NotCreatedIssueId)
	assert.NotNil(tickets)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketsOpeningResults")), jiraResponse)
	fmt.Println("numberIssueCreated :", numberIssueCreated)

	return
}

func TestOpenJiraTicketWithProjectKeyFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraTickets("/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue")

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnsForJira.json"), &vulnsForJira)
	if err != nil {
		panic(err)
	}

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = ""
	Mf.jiraProjectKey = "Key"

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
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.Equal("", NotCreatedIssueId)
	assert.NotNil(tickets)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketsOpeningResults")), jiraResponse)
	fmt.Println("numberIssueCreated :", numberIssueCreated)

	return
}

func TestOpenJiraTicketErrorAndRetryFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraTicketsWithError("/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue")

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnsForJira.json"), &vulnsForJira)
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
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	removeLogFile()

	assert.Equal("", NotCreatedIssueId)
	assert.NotNil(tickets)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketsOpeningResults")), jiraResponse)
	fmt.Println(numberIssueCreated)

	return
}

func TestOpenJiraMultipleTicketsErrorAndRetryFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraMultipleTicketsWithError()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnsForJiraList.json"), &vulnsForJira)
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
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.NotNil(tickets)
	assert.Equal("", NotCreatedIssueId)
	fmt.Println(numberIssueCreated)

	// Read fixture file line by line
	file, err := os.Open("./fixtures/results/jiraMultipleTicketsOpeningResultsWithOneFailure")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// assert if the line is not in the jira response
	for scanner.Scan() {
		assert.Contains(jiraResponse, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	removeLogFile()

	return
}

func TestOpenJiraMultipleTicketsErrorAndRetryAndFailFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraMultipleTicketsWithErrorTwice()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnsForJiraList.json"), &vulnsForJira)
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
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.Equal(string(readFixture("./fixtures/results/NotCreatedIssueIdSingle")), NotCreatedIssueId)
	assert.NotNil(numberIssueCreated)
	assert.NotNil(tickets)

	// Read fixture file line by line
	file, err := os.Open("./fixtures/results/jiraMultipleTicketsOpeningResultsWithOneFailure")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// assert if the line is not in the jira response
	for scanner.Scan() {
		assert.Contains(jiraResponse, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	removeLogFile()

	return
}

// Ticket could not be created
func TestOpenJiraMultipleTicketsFailureFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraMultipleTicketsFailure()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnsForJiraList.json"), &vulnsForJira)
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
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	//endpointAPI string, orgID string, token string, jiraProjectID string, jiraProjectKey string, jiraTicketType string, assigneeID string, labels string, projectInfo jsn.Json, vulnForJira interface{}, priorityIsSeverity bool
	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	fmt.Println(numberIssueCreated)
	assert.NotNil(tickets)

	// Read fixture file line by line
	file, err := os.Open("./fixtures/results/NotCreatedIssueIdsMultiple")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// assert if the line is not in the jira response
	for scanner.Scan() {
		assert.Contains(NotCreatedIssueId, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	assert.Equal("", jiraResponse)
	removeLogFile()

	return
}

func TestOpenJiraTicketWithAssigneeIDFunc(t *testing.T) {
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
	Of.assigneeID = "12345"
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

	CreateLogFile(cD, "ErrorsFile_")

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}

	assert.NotNil(tickets)
	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketWithoutLabelsWithAssigneeID.json")), string(mirroredResponse.Body))
	fmt.Println("numberIssueCreated :", numberIssueCreated)

	removeLogFile()

	return
}

func TestOpenJiraTicketDryRun(t *testing.T) {

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
	Of.assigneeID = "12345"
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = true
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	removeLogFile()

	assert.NotNil(tickets)
	assert.Equal(jiraResponse, "")
	assert.Equal(numberIssueCreated, 0)
	assert.Equal(NotCreatedIssueId, "")

	return
}

func TestOpenJiraMultipleTicketsIsUpgradableFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraMultipleTickets()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnForJiraAggregatedWithPathList.json"), &vulnsForJira)
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
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = true
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)
	CreateLogFile(cD, "ErrorsFile_")

	NumberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	fmt.Println(NotCreatedIssueId)
	assert.NotNil(tickets)
	assert.Equal("VulnID SNYK-JS-MINIMIST-559765 ticket not created : Skipping creating ticket for Remote Code Execution (RCE) because no upgrade is available.", NotCreatedIssueId)
	assert.Equal(NumberIssueCreated, 1)

	// Read fixture file line by line
	file, err := os.Open("./fixtures/results/jiraMultipleTicketsOpeningResultsIsUpgradable")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// assert if the line is not in the jira response
	for scanner.Scan() {
		assert.Contains(jiraResponse, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	// Delete the file created for the test
	removeLogFile()

	return
}

func TestOpenJiraMultipleTicketsifAutoFixableOnlyFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraMultipleTickets()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnForJiraAggregatedWithPathList.json"), &vulnsForJira)
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
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = true

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)
	CreateLogFile(cD, "ErrorsFile_")

	NumberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	fmt.Println(NotCreatedIssueId)
	assert.NotNil(tickets)
	assert.Equal("", NotCreatedIssueId)
	assert.Equal(NumberIssueCreated, 2)

	// Read fixture file line by line
	file, err := os.Open("./fixtures/results/jiraMultipleTicketsOpeningResultsIsUpgradable")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// assert if the line is not in the jira response
	for scanner.Scan() {
		assert.Contains(jiraResponse, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	// Delete the file created for the test
	removeLogFile()

	return
}

func TestOpenJiraSingleTicketIfAutoFixableOnlyFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraMultipleTickets()

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnForJiraAggregatedWithPathList2.json"), &vulnsForJira)
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
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = true

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)
	CreateLogFile(cD, "ErrorsFile_")

	NumberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	fmt.Println(NotCreatedIssueId)
	assert.NotNil(tickets)
	assert.Equal("VulnID SNYK-JS-MINIMIST-559765 ticket not created : Skipping creating ticket for Remote Code Execution (RCE) because no fix is available.", NotCreatedIssueId)
	assert.Equal(NumberIssueCreated, 1)

	// Read fixture file line by line
	file, err := os.Open("./fixtures/results/jiraMultipleTicketsOpeningResultsIsUpgradable")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// assert if the line is not in the jira response
	for scanner.Scan() {
		assert.Contains(jiraResponse, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}

	// Delete the file created for the test
	removeLogFile()

	return
}

func TestOpenJiraTicketDryRyn(t *testing.T) {

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
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = true
	Of.cveInTitle = true
	Of.ifUpgradeAvailableOnly = true
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	removeLogFile()

	assert.NotNil(tickets)
	assert.Equal(jiraResponse, "")
	assert.Equal(numberIssueCreated, 0)
	assert.Equal(NotCreatedIssueId, "")

	return

}

func TestOpenJiraTicketDryRunifAutoFixableOnly(t *testing.T) {

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
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = true
	Of.cveInTitle = true
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = true

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	removeLogFile()

	assert.NotNil(tickets)
	assert.Equal(jiraResponse, "")
	assert.Equal(numberIssueCreated, 0)
	assert.Equal(NotCreatedIssueId, "VulnID SNYK-JS-MINIMIST-559764 ticket not created : Skipping creating ticket for Remote Code Execution (RCE) because no fix is available.")

	return

}

func TestAddMandatoryFieldToTicket(t *testing.T) {

	assert := assert.New(t)
	ticket := readFixture("./fixtures/ticketJson.json")

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	customMandatoryJiraFields := map[string]interface{}{"Something": map[string]interface{}{"value": "This is a summary"}, "transition": map[string]interface{}{"id": 5}}

	newTicket := addMandatoryFieldToTicket(ticket, customMandatoryJiraFields, cD)
	newTicketFixture := readFixture("./fixtures/ticketJsonWithMandatoryField.json")

	assert.Equal(string(newTicket), string(newTicketFixture))
	removeLogFile()
}

func TestAddNestedMandatoryFieldToTicket(t *testing.T) {

	assert := assert.New(t)
	ticket := readFixture("./fixtures/ticketJson.json")

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	customMandatoryJiraFields := map[string]interface{}{"something": map[string]interface{}{"somethingElse": map[string]interface{}{"value": "This is a summary"}}, "transition": map[string]interface{}{"id": 5}}

	newTicket := addMandatoryFieldToTicket(ticket, customMandatoryJiraFields, cD)

	newTicketFixture := readFixture("./fixtures/ticketJsonWithNestedMandatoryField.json")

	assert.Equal(string(newTicket), string(newTicketFixture))
	removeLogFile()
}
func TestAddMandatoryFieldToTicketCustomField(t *testing.T) {

	assert := assert.New(t)
	ticket := readFixture("./fixtures/ticketJson.json")

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	customMandatoryJiraFields := map[string]interface{}{"customfield_10601": []map[string]string{map[string]string{"name": "Value1"}, map[string]string{"name": "Value2"}}, "transition": map[string]interface{}{"id": 5}}

	newTicket := addMandatoryFieldToTicket(ticket, customMandatoryJiraFields, cD)

	newTicketFixture := readFixture("./fixtures/ticketJsonWithMandatoryFieldCustomJiraValue.json")

	assert.Equal(string(newTicket), string(newTicketFixture))
	removeLogFile()
}

func TestAddMandatoryFieldToTicketCustomFieldLabel(t *testing.T) {

	assert := assert.New(t)
	ticket := readFixture("./fixtures/ticketJson.json")

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	customMandatoryJiraFields := map[string]interface{}{"customfield_10601": []string{"Value1", "Value2"}, "transition": map[string]interface{}{"id": 5}}

	newTicket := addMandatoryFieldToTicket(ticket, customMandatoryJiraFields, cD)

	newTicketFixture := readFixture("./fixtures/ticketJsonWithMandatoryFieldCustomJiraValueLabel.json")

	assert.Equal(string(newTicket), string(newTicketFixture))
	removeLogFile()
}

func TestAddMandatoryFieldToTicketCustomFieldSimpleField(t *testing.T) {

	assert := assert.New(t)
	ticket := readFixture("./fixtures/ticketJson.json")

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	customMandatoryJiraFields := map[string]interface{}{"customfield_10601": "some value to add to the ticket", "transition": map[string]interface{}{"id": 5}}

	newTicket := addMandatoryFieldToTicket(ticket, customMandatoryJiraFields, cD)

	newTicketFixture := readFixture("./fixtures/ticketJsonWithMandatoryFieldCustomJiraValueSimpleField.json")

	assert.Equal(string(newTicket), string(newTicketFixture))
	removeLogFile()
}

func TestOpenJiraTicketError50xAndRetryFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraTicketsWithError50x("/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue")

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnsForJira.json"), &vulnsForJira)
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
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.NotNil(tickets)
	assert.Equal("", NotCreatedIssueId)
	assert.Equal(numberIssueCreated, 1)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketsOpeningResults")), jiraResponse)

	removeLogFile()

	return
}

// Test openJiraTickets function
func TestOpenJiraTicketWithDueDateFunc(t *testing.T) {
	assert := assert.New(t)
	server := HTTPResponseCheckOpenJiraTickets("/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue")

	defer server.Close()

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	vulnsForJira := make(map[string]interface{})
	err := json.Unmarshal(readFixture("./fixtures/vulnsForJira.json"), &vulnsForJira)
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
	Of.dueDate = "2029-01-01"
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

	numberIssueCreated, jiraResponse, NotCreatedIssueId, tickets := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.Equal("", NotCreatedIssueId)
	assert.NotNil(tickets)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketsOpeningResults")), jiraResponse)
	fmt.Println("numberIssueCreated :", numberIssueCreated)

	return
}
