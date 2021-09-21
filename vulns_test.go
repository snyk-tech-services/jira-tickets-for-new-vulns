package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test getVulnsWithoutTicket function
func TestGetVulnsWithoutTicketFunc(t *testing.T) {

	//getVulnsWithoutTicket(endpointAPI string, orgID string, projectID string, token string, severity string, issueType string, tickets map[string]string) []interface{} {
	//return []interface, array of vulns
	// get http server to return projectIssuesPerPath.json like API would
	// compare []interface with projectVulnsPerPath.json

	assert := assert.New(t)

	server := HTTPResponseCheckAndStub_()

	defer server.Close()

	var tickets map[string]string
	tickets = make(map[string]string)
	// Simulate an existing ticket for that vuln
	tickets["SNYK-JS-PACRESOLVER-1564857"] = "FPI-794"
	var maturityLevels []string
	response := getVulnsWithoutTicket(server.URL, "123", "123", "123", "low", maturityLevels, 0, "all", tickets)
	//fmt.Println(response)
	assert.Equal(2, len(response))

	return
}
