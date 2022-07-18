package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

/// test flags setting
func TestSetOptionFunc(t *testing.T) {

	assert := assert.New(t)

	// reset command line arg
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	args := []string{
		"--token=123",
		"--configFile=./fixtures",
	}

	options := flags{}
	options.setOption(args)

	mandatoryResult := &MandatoryFlags{
		orgID:         "0e9373a6-f858-11ec-b939-0242ac120002",
		apiToken:      "123",
		jiraProjectID: "15698",
		endpointAPI:   "https://snyk.io/api",
	}

	optionalResult := &optionalFlags{
		assigneeID:             "1238769",
		assigneeName:           "",
		debug:                  false,
		dryRun:                 false,
		issueType:              "vuln",
		jiraTicketType:         "Task",
		labels:                 "",
		maturityFilterString:   "proof-of-concept",
		priorityIsSeverity:     true,
		priorityScoreThreshold: 20,
		projectID:              "",
		severity:               "critical",
	}

	assert.Equal(optionalResult, &options.optionalFlags)
	assert.Equal(mandatoryResult, &options.mandatoryFlags)
}

//checking that the option override the configFile
func TestSetOptionMixFunc(t *testing.T) {

	assert := assert.New(t)

	// reset command line arg
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	args := []string{
		"--token=123",
		"--type=license",
		"--assigneeId=654",
		"--api=http://snyk.io/api",
		"--configFile=./fixtures",
		"--orgID=0e9373a6-f858-11ec-b939-0242ac120002",
		"--jiraProjectID=15699",
	}

	options := flags{}
	options.setOption(args)

	mandatoryResult := &MandatoryFlags{
		orgID:         "0e9373a6-f858-11ec-b939-0242ac120002",
		apiToken:      "123",
		jiraProjectID: "15699",
		endpointAPI:   "http://snyk.io/api",
	}

	optionalResult := &optionalFlags{
		assigneeID:             "654",
		assigneeName:           "",
		debug:                  false,
		dryRun:                 false,
		issueType:              "license",
		jiraTicketType:         "Task",
		labels:                 "",
		maturityFilterString:   "proof-of-concept",
		priorityIsSeverity:     true,
		priorityScoreThreshold: 20,
		projectID:              "",
		severity:               "critical",
	}

	assert.Equal(optionalResult, &options.optionalFlags)
	assert.Equal(mandatoryResult, &options.mandatoryFlags)
}

func TestSetOption(t *testing.T) {

	assert := assert.New(t)

	options := flags{}

	// reset command line arg
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = append(os.Args, "--orgID=123")
	os.Args = append(os.Args, "--token=123")
	os.Args = append(os.Args, "--jiraProjectID=123")
	os.Args = append(os.Args, "--api=https://test.com")
	os.Args = append(os.Args, "--configFile=./fixtures/yamlFileForMandatoryFieldTest")

	options.setOption(os.Args)

	mandatoryResult := &MandatoryFlags{
		orgID:         "123",
		apiToken:      "123",
		jiraProjectID: "123",
		endpointAPI:   "https://test.com",
	}

	optionalResult := &optionalFlags{
		assigneeID:             "1238769",
		assigneeName:           "",
		debug:                  false,
		dryRun:                 false,
		issueType:              "vuln",
		jiraTicketType:         "Task",
		labels:                 "",
		maturityFilterString:   "proof-of-concept",
		priorityIsSeverity:     true,
		priorityScoreThreshold: 20,
		projectID:              "",
		severity:               "critical",
	}

	customMandatoryJiraFields := map[string]interface{}{"Something": map[string]interface{}{"Value": "This is a summary"}, "transition": map[string]interface{}{"id": 5}}

	assert.Equal(optionalResult, &options.optionalFlags)
	assert.Equal(mandatoryResult, &options.mandatoryFlags)
	assert.Equal(customMandatoryJiraFields, options.customMandatoryJiraFields)

}
