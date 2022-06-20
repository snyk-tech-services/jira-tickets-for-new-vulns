package main

import (
	"encoding/json"
	"log"
	"strings"
	"testing"

	"github.com/nsf/jsondiff"
	"github.com/stretchr/testify/assert"
)

// Test GetProjectDetails function
func TestGetProjectDetailsFunc(t *testing.T) {
	expectedTestURL := "/v1/org/123/project/123"
	assert := assert.New(t)
	server := HTTPResponseCheckAndStub(expectedTestURL, "project")

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	response, _ := getProjectDetails(Mf, "123", cD)

	opts := jsondiff.DefaultConsoleOptions()
	marshalledResp, _ := json.Marshal(response)
	comparison, _ := jsondiff.Compare(readFixture("./fixtures/project.json"), marshalledResp, &opts)
	assert.Equal("FullMatch", comparison.String())

	return
}

// Test GetProjectDetails function
func TestGetOrgProjects(t *testing.T) {
	expectedTestURL := "/v1/org/123/projects"
	assert := assert.New(t)
	server := HTTPResponseCheckAndStub(expectedTestURL, "org")

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	response, _ := getOrgProjects(Mf, cD)

	opts := jsondiff.DefaultConsoleOptions()
	marshalledResp, _ := json.Marshal(response)
	comparison, _ := jsondiff.Compare(readFixture("./fixtures/org.json"), marshalledResp, &opts)
	assert.Equal("FullMatch", comparison.String())

	return
}

// Test getProjectsIds function
func TestGetProjectsIdsAllProjects(t *testing.T) {

	expectedTestURL := "/v1/org/123/projects"
	assert := assert.New(t)
	server := HTTPResponseCheckAndStub(expectedTestURL, "org")

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
	Of.severityThreshold = ""
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

	list, er := getProjectsIds(flags, cD)
	listString := "[" + strings.Join(list, ",") + "]"

	if er != nil {
		log.Fatal()
	}

	ResultList := readFixture("./fixtures/results/projectIdsList.txt")
	assert.Equal(string(ResultList), listString)

	return
}
