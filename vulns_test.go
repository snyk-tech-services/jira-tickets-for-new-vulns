package main

import (
	"encoding/json"
	"testing"

	"github.com/michael-go/go-jsn/jsn"
	"github.com/nsf/jsondiff"
	"github.com/stretchr/testify/assert"
)

// Test consolidateAllPathsIntoSingleVuln function
func TestConsolidateAllPathsIntoSingleVulnFunc(t *testing.T) {

	assert := assert.New(t)
	vulnsPerPathFixture := readFixture("./fixtures/projectIssuesPerPath.json")
	vulnsPerPathJSON, _ := jsn.NewJson(vulnsPerPathFixture)
	var vulnsPerPath []interface{}
	for _, e := range vulnsPerPathJSON.K("issues").K("vulnerabilities").Array().Elements() {
		vulnsPerPath = append(vulnsPerPath, e)
	}
	consolidatedVulns := consolidateAllPathsIntoSingleVuln(vulnsPerPath)

	consolidatedVulnsFixture := readFixture("./fixtures/results/projectIssuesConsolidatedPaths.json")
	consolidatedVulnsFixtureJSON, _ := jsn.NewJson(consolidatedVulnsFixture)

	for _, e := range consolidatedVulnsFixtureJSON.K("issues").K("vulnerabilities").Array().Elements() {

		opts := jsondiff.DefaultConsoleOptions()
		marshalledConsolidatedVuln, _ := json.Marshal(consolidatedVulns[e.K("id").String().Value])

		comparison, _ := jsondiff.Compare(readFixture("./fixtures/results/projectIssuesConsolidatedPaths.json"), marshalledConsolidatedVuln, &opts)

		assert.Equal("FullMatch", comparison)
	}

	return
}

// Test getVulnsWithoutTicket function
func TestGetVulnsWithoutTicketFunc(t *testing.T) {

	//getVulnsWithoutTicket(endpointAPI string, orgID string, projectID string, token string, severity string, issueType string, tickets map[string]string) []interface{} {
	//return []interface, array of vulns
	// get http server to return projectIssuesPerPath.json like API would
	// compare []interface with projectVulnsPerPath.json

	assert := assert.New(t)

	server := HTTPResponseCheckAndStub("/v1/org/123/project/123/issues", "projectIssuesPerPath")

	defer server.Close()

	var tickets map[string]string
	tickets = make(map[string]string)
	// Simulate an existing ticket for that vuln
	tickets["npm:growl:20160721"] = "FPI-796"
	response := getVulnsWithoutTicket(server.URL, "123", "123", "123", "low", "all", tickets)
	assert.Equal(4, len(response))

	return
}
