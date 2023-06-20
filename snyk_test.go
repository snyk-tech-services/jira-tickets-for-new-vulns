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

	CreateLogFile(cD, "ErrorsFile_")

	response, _ := getProjectDetails(Mf, "123", cD)

	opts := jsondiff.DefaultConsoleOptions()
	marshalledResp, _ := json.Marshal(response)
	comparison, _ := jsondiff.Compare(readFixture("./fixtures/project.json"), marshalledResp, &opts)
	assert.Equal("FullMatch", comparison.String())

	removeLogFile()

	return
}

// Test get projects details with error 400
func TestGetProjectDetailsErrorFunc(t *testing.T) {
	expectedTestURL := "/v1/org/123/project/123"
	assert := assert.New(t)
	server := HTTPResponseCheckAndStubError(expectedTestURL, "project")

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

	CreateLogFile(cD, "ErrorsFile_")

	_, err := getProjectDetails(Mf, "123", cD)
	assert.Contains(err.Error(), "Failure, Could not read the Project detail for endpoint")

	removeLogFile()

	return
}

// Test get projevs with error 500

// Test GetProjectDetails function
func TestGetOrgProjects(t *testing.T) {
	expectedTestURL := "/rest/orgs/123/projects?version=2022-07-08~beta&status=active&limit=100"
	assert := assert.New(t)
	server := HTTPResponseCheckAndStub(expectedTestURL, "org")

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"

	// setting optional options
	Of := optionalFlags{}

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	response, _ := getOrgProjects(flags, cD)

	opts := jsondiff.DefaultConsoleOptions()
	marshalledResp, _ := json.Marshal(response)

	fixture := readFixtureData("./fixtures/org.json")
	comparison, _ := jsondiff.Compare(fixture, marshalledResp, &opts)
	assert.Equal("FullMatch", comparison.String())

	removeLogFile()

	return
}

// Test GetProjectDetails function with a criticality filter
func TestGetOrgProjectsCriticality(t *testing.T) {
	expectedTestURL := "/rest/orgs/123/projects?version=2022-07-08~beta&status=active&limit=100&businessCriticality=critical"
	assert := assert.New(t)
	server := HTTPResponseCheckAndStub(expectedTestURL, "org")

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"

	// setting optional options
	Of := optionalFlags{}
	Of.projectCriticality = "critical"

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	response, _ := getOrgProjects(flags, cD)

	opts := jsondiff.DefaultConsoleOptions()
	marshalledResp, _ := json.Marshal(response)
	comparison, _ := jsondiff.Compare(readFixtureData("./fixtures/org.json"), marshalledResp, &opts)
	assert.Equal("FullMatch", comparison.String())

	removeLogFile()

	return
}

// Test GetProjectDetails function with an environment filter
func TestGetOrgProjectsEnvironment(t *testing.T) {
	expectedTestURL := "/rest/orgs/123/projects?version=2022-07-08~beta&status=active&limit=100&environment=frontend%2Cexternal"
	assert := assert.New(t)
	server := HTTPResponseCheckAndStub(expectedTestURL, "org")

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"

	// setting optional options
	Of := optionalFlags{}
	Of.projectEnvironment = "frontend,external"

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	response, _ := getOrgProjects(flags, cD)

	opts := jsondiff.DefaultConsoleOptions()
	marshalledResp, _ := json.Marshal(response)
	comparison, _ := jsondiff.Compare(readFixtureData("./fixtures/org.json"), marshalledResp, &opts)
	assert.Equal("FullMatch", comparison.String())

	removeLogFile()

	return
}

// Test GetProjectDetails function with a lifecycle filter
func TestGetOrgProjectsLifecycle(t *testing.T) {
	expectedTestURL := "/rest/orgs/123/projects?version=2022-07-08~beta&status=active&limit=100&lifecycle=production"
	assert := assert.New(t)
	server := HTTPResponseCheckAndStub(expectedTestURL, "org")

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"

	// setting optional options
	Of := optionalFlags{}
	Of.projectLifecycle = "production"

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	response, _ := getOrgProjects(flags, cD)

	opts := jsondiff.DefaultConsoleOptions()
	marshalledResp, _ := json.Marshal(response)
	comparison, _ := jsondiff.Compare(readFixtureData("./fixtures/org.json"), marshalledResp, &opts)
	assert.Equal("FullMatch", comparison.String())

	removeLogFile()

	return
}

// Test getProjectsIds function
func TestGetProjectsIdsAllProjects(t *testing.T) {

	expectedTestURL := "/rest/orgs/123/projects?version=2022-07-08~beta&status=active&limit=100"
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

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	filenameNotCreated := CreateLogFile(cD, "ErrorsFile_")

	list, er := getProjectsIds(flags, cD, filenameNotCreated)
	listString := "[" + strings.Join(list, ",") + "]"

	if er != nil {
		log.Fatal()
	}

	// Delete the file created for the test
	removeLogFile()

	ResultList := readFixture("./fixtures/results/projectIdsList.txt")
	assert.Equal(string(ResultList), listString)

	return
}
