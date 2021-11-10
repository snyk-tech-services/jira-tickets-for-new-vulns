package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
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
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.Equal("", NotCreatedIssueId)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketsOpeningResults")), jiraResponse)
	fmt.Println("NumberIssueCreated :", NumberIssueCreated)

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
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.Equal("", NotCreatedIssueId)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketsOpeningResults")), jiraResponse)
	fmt.Println("NumberIssueCreated :", NumberIssueCreated)

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
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.Equal("", NotCreatedIssueId)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketsOpeningResults")), jiraResponse)
	fmt.Println(NumberIssueCreated)

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
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.Equal("", NotCreatedIssueId)
	fmt.Println(NumberIssueCreated)

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

	// Delete the file created for the test
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
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	assert.Equal(string(readFixture("./fixtures/results/NotCreatedIssueIdSingle")), NotCreatedIssueId)
	fmt.Println(NumberIssueCreated)

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

	// Delete the file created for the test
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
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = true
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	//endpointAPI string, orgID string, token string, jiraProjectID string, jiraProjectKey string, jiraTicketType string, assigneeName string, assigneeID string, labels string, projectInfo jsn.Json, vulnForJira interface{}, priorityIsSeverity bool
	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	fmt.Println(NumberIssueCreated)

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

	// Delete the file created for the test
	removeLogFile()

	assert.Equal("", jiraResponse)

	return
}

func TestOpenJiraTicketWithAssigneeNameFunc(t *testing.T) {
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
	Of.assigneeName = "admin"
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	numberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}

	// Delete the file created for the test
	removeLogFile()

	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketWithoutLabelsWithAssigneeName.json")), string(mirroredResponse.Body))
	fmt.Println("NumberIssueCreated :", numberIssueCreated)

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
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	numberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}

	// Delete the file created for the test
	removeLogFile()

	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketWithoutLabelsWithAssigneeID.json")), string(mirroredResponse.Body))
	fmt.Println("NumberIssueCreated :", numberIssueCreated)

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
	Of.assigneeID = "12345"
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.dryRun = true

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)
	numberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(flags, projectInfo, vulnsForJira, cD)

	// Delete the file created for the test
	removeLogFile()

	assert.Equal(jiraResponse, "")
	assert.Equal(numberIssueCreated, 0)
	assert.Equal(NotCreatedIssueId, "")

	return
}

func TestAddToTicketFile(t *testing.T) {

	assert := assert.New(t)

	dat, err := ioutil.ReadFile("./fixtures/ticketJson.json")
	if err != nil {
		log.Fatal()
	}

	expectedResult, err := ioutil.ReadFile("./fixtures/results/logFile.log")
	if err != nil {
		log.Fatal()
	}
	// setting debug
	cD := debug{}
	cD.setDebug(false)

	AddToTicketFile(dat, []byte("123"), cD)

	// Find logfile created
	path, found := findLogFile()

	assert.FileExists(path)
	assert.True(found)

	fileCreated, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal()
	}

	assert.Equal(expectedResult, fileCreated)

	// Delete the file created for the test
	removeLogFile()

	return
}
