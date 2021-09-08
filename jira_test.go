package main

import (
	"encoding/json"
	"fmt"
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
	jiraResponse, err := openJiraTickets(server.URL, "123", "123", "123", "Bug", "", "", projectInfo, vulnsForJira, false)
	if err != nil {
		panic(err)
	}
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketsOpeningResults")), jiraResponse)

	//expectedTestURL := "/v1/org/"+orgID+"/project/"+projectInfo.K("id").String().Value+"/issue/"+vulnID+"/jira-issue"
	//"/v1/org/123/project/123/jira-issues"

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
	jiraResponse, err := openJiraTickets(server.URL, "123", "123", "123", "Bug", "", "", projectInfo, vulnsForJira, true)
	if err != nil {
		panic(err)
	}
	fmt.Println(jiraResponse)
	assert.Equal(string(readFixture("./fixtures/results/jiraTicketsOpeningResults")), jiraResponse)

	return
}
