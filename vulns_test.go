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

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "123"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "123"
	Mf.jiraProjectID = "123"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	Of.severity = "low"
	Of.priorityScoreThreshold = 0
	Of.issueType = "all"
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.assigneeName = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	var tickets map[string]string
	tickets = make(map[string]string)
	// Simulate an existing ticket for that vuln
	tickets["SNYK-JS-PACRESOLVER-1564857"] = "FPI-794"
	var maturityLevels []string

	response := getVulnsWithoutTicket(flags, "123", maturityLevels, tickets, cD)
	//fmt.Println(response)
	assert.Equal(2, len(response))

	return
}
