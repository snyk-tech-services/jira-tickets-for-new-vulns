package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test getVulnsWithoutTicket function
func TestGetVulnsWithoutTicketFunc(t *testing.T) {

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
	//Of.severity = "low"
	Of.severityArray = "critical,low"
	Of.priorityScoreThreshold = 0
	Of.issueType = "all"
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	var tickets map[string]string
	tickets = make(map[string]string)
	// Simulate an existing ticket for that vuln
	tickets["SNYK-JS-PACRESOLVER-1564857"] = "FPI-794"
	var maturityLevels []string

	response, skippedIssues, _ := getVulnsWithoutTicket(flags, "123", maturityLevels, tickets, cD)
	assert.Equal(0, len(skippedIssues))
	assert.Equal(2, len(response))

	removeLogFile()

	return
}

// Test that we ignore any issue that is not of type license or a vuln
// only vuln and license can be in the same aggregated issue reponse atm
// IAC are separated projects with only configuration type
// snyk code is in a separated API atm

func TestNoVulnOrLicense(t *testing.T) {

	assert := assert.New(t)

	server := HTTPResponseCheckAndStubNoVulnOrLicense()

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
	//Of.severity = "low"
	Of.severityArray = "critical,low"
	Of.priorityScoreThreshold = 0
	Of.issueType = "all"
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	CreateLogFile(cD, "ErrorsFile_")

	var tickets map[string]string
	tickets = make(map[string]string)
	var maturityLevels []string

	response, skippedIssues, _ := getVulnsWithoutTicket(flags, "123", maturityLevels, tickets, cD)

	assert.Equal(0, len(response))
	assert.Equal(0, len(skippedIssues))

	removeLogFile()

	return
}

func TestGetVulnsWithoutTicketErrorRetrievingDataFunc(t *testing.T) {

	assert := assert.New(t)

	server := HTTPResponseCheckAndStubWithError_()

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
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

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

	CreateLogFile(cD, "ErrorsFile_")

	response, skippedIssues, _ := getVulnsWithoutTicket(flags, "123", maturityLevels, tickets, cD)

	assert.Equal(2, len(response))
	assert.GreaterOrEqual(len(skippedIssues), 1)

	removeLogFile()
	return
}

func TestGetLicenseWithoutTicketFunc(t *testing.T) {

	assert := assert.New(t)

	server := HTTPResponseCheckAndStub_()

	defer server.Close()

	// setting mandatory options
	Mf := MandatoryFlags{}
	Mf.orgID = "456"
	Mf.endpointAPI = server.URL
	Mf.apiToken = "456"
	Mf.jiraProjectID = "456"
	Mf.jiraProjectKey = ""

	// setting optional options
	Of := optionalFlags{}
	Of.severity = "low"
	Of.priorityScoreThreshold = 0
	Of.issueType = "all"
	Of.debug = false
	Of.jiraTicketType = "Bug"
	Of.assigneeID = ""
	Of.labels = ""
	Of.priorityIsSeverity = false
	Of.projectID = ""
	Of.maturityFilterString = ""
	Of.ifUpgradeAvailableOnly = false
	Of.ifAutoFixableOnly = false

	flags := flags{}
	flags.mandatoryFlags = Mf
	flags.optionalFlags = Of

	// setting debug
	cD := debug{}
	cD.setDebug(false)

	var maturityLevels []string

	CreateLogFile(cD, "ErrorsFile_")

	response, skippedIssues, _ := getVulnsWithoutTicket(flags, "456", maturityLevels, nil, cD)
	assert.Equal(0, len(skippedIssues))
	assert.Equal(1, len(response))

	removeLogFile()

	return
}
