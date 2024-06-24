package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/michael-go/go-jsn/jsn"
	"github.com/stretchr/testify/assert"
)

func TestFormatJiraTicketFunc(t *testing.T) {

	projectInfo, _ := jsn.NewJson(readFixture("./fixtures/project.json"))
	issueData, _ := jsn.NewJson(readFixture("./fixtures/vulnForJiraAggregatedWithPathForTicketTest.json"))

	flags := flags{}
	flags.optionalFlags.cveInTitle = true

	jiraTicket := formatJiraTicket(issueData, projectInfo, flags)

	// Convert jira ticket into a string
	ticket := fmt.Sprintf("%v", jiraTicket)

	file, err := os.Open("./fixtures/ticket.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		compare := strings.Contains(ticket, scanner.Text())
		assert.Equal(t, compare, true)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
