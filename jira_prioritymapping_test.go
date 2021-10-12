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
	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "123", "Bug", "", "", projectInfo, vulnsForJira, true)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}
	fmt.Println(NumberIssueCreated)
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

	err := json.Unmarshal(readFixture("./fixtures/vulnsForJira.json"), &vulnsForJira)
	if err != nil {
		panic(err)
	}
	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "123", "Bug", "", "", projectInfo, vulnsForJira, false)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}
	fmt.Println(NumberIssueCreated)
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
	NumberIssueCreated, jiraResponse, NotCreatedIssueId := openJiraTickets(server.URL, "123", "123", "123", "Bug", "", "", projectInfo, vulnsForJira, true)

	var mirroredResponse mirroredResponse
	if err := json.Unmarshal([]byte(jiraResponse), &mirroredResponse); err != nil {
		panic(err)
	}
	fmt.Println(NumberIssueCreated)
	assert.Equal(NotCreatedIssueId, "")
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketWithCustomPriorityMapping.json")), string(mirroredResponse.Body))

	return
}
