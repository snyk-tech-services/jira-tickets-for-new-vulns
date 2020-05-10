package main

import (
	"encoding/json"
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

	response := getProjectDetails(server.URL, "123", "123", "123")

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

	response := getOrgProjects(server.URL, "123", "123")

	opts := jsondiff.DefaultConsoleOptions()
	marshalledResp, _ := json.Marshal(response)
	comparison, _ := jsondiff.Compare(readFixture("./fixtures/org.json"), marshalledResp, &opts)
	assert.Equal("FullMatch", comparison.String())

	return
}
