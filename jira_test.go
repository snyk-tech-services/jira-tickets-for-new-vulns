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
	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "123", "", "Bug", "", "", "", projectInfo, vulnsForJira, false)

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
	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "", "Key", "Bug", "", "", "", projectInfo, vulnsForJira, false)

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
	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "123", "", "Bug", "", "", "", projectInfo, vulnsForJira, true)

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

	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "123", "", "Bug", "", "", "", projectInfo, vulnsForJira, true)

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

	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "123", "", "Bug", "", "", "", projectInfo, vulnsForJira, true)

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

	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "123", "", "Bug", "", "", "", projectInfo, vulnsForJira, true)

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
	numberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "123", "", "Bug", "admin", "", "", projectInfo, vulnsForJira, false)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}
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
	numberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "123", "", "Bug", "", "12345", "", projectInfo, vulnsForJira, false)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}
	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketWithoutLabelsWithAssigneeID.json")), string(mirroredResponse.Body))
	fmt.Println("NumberIssueCreated :", numberIssueCreated)

	return
}
