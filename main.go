package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {

	asciiArt :=
		`
================================================
  _____             _      _______        _     
 / ____|           | |    |__   __|      | |    
| (___  _ __  _   _| | __    | | ___  ___| |__  
 \___ \| '_ \| | | | |/ /    | |/ _ \/ __| '_ \ 
 ____) | | | | |_| |   <     | |  __/ (__| | | |
|_____/|_| |_|\__, |_|\_\    |_|\___|\___|_| |_|
              __/ /                            
             |___/                             
================================================
JIRA Syncing Tool
Open Source, so feel free to contribute !
================================================
`

	fmt.Println(asciiArt)

	orgIDPtr := flag.String("orgID", "", "Your Snyk Organization ID (check under Settings)")
	projectIDPtr := flag.String("projectID", "", "Optional. Your Project ID. Will sync all projects of your organization if not provided")
	endpointAPIPtr := flag.String("api", "https://snyk.io/api", "Optional. Your API endpoint for onprem deployments (https://yourdeploymenthostname/api)")
	apiTokenPtr := flag.String("token", "", "Your API token")
	jiraProjectIDPtr := flag.String("jiraProjectID", "", "Your JIRA projectID")
	jiraTicketTypePtr := flag.String("jiraTicketType", "Bug", "Optional. Chosen JIRA ticket type")
	severityPtr := flag.String("severity", "low", "Optional. Your severity threshold")
	maturityFilterPtr := flag.String("maturityFilter", "", "Optional. include only maturity level(s) separated by commas [mature,proof-of-concept,no-known-exploit,no-data]")
	typePtr := flag.String("type", "all", "Optional. Your issue type (all|vuln|license)")
	assigneeIDPtr := flag.String("assigneeId", "", "Optional. The Jira user ID to assign issues to")
	labelsPtr := flag.String("labels", "", "Optional. Jira ticket labels")
	priorityIsSeverityPtr := flag.Bool("priorityIsSeverity", false, "Use issue severity as priority")
	priorityScorePtr := flag.Int("priorityScoreThreshold", 0, "Optional. Your min priority score threshold [INT between 0 and 1000]")
	flag.Parse()

	var orgID string = *orgIDPtr
	var projectID string = *projectIDPtr
	var endpointAPI string = *endpointAPIPtr
	var apiToken string = *apiTokenPtr
	var jiraProjectID string = *jiraProjectIDPtr
	var jiraTicketType string = *jiraTicketTypePtr
	var severity string = *severityPtr
	var issueType string = *typePtr
	var maturityFilterString string = *maturityFilterPtr
	var assigneeID string = *assigneeIDPtr
	var labels string = *labelsPtr
	var priorityIsSeverity bool = *priorityIsSeverityPtr
	var priorityScoreThreshold int = *priorityScorePtr

	if len(orgID) == 0 || len(apiToken) == 0 || len(jiraProjectID) == 0 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	projectIDs, er := getProjectsIds(projectID, endpointAPI, orgID, apiToken)

	if er != nil {
		log.Fatal(er)
	}

	if priorityScoreThreshold < 0 || priorityScoreThreshold > 1000 {
		log.Fatalf("INPUT ERROR: %d is not a valid score. Must be between 0-1000.", priorityScoreThreshold)
	}

	maturityFilter := createMaturityFilter(strings.Split(maturityFilterString, ","))
	numberIssueCreated := 0
	notCreatedJiraIssues := ""
	jiraResponse := ""

	for _, project := range projectIDs {

		fmt.Println("1/4 - Retrieving Project", project)
		projectInfo := getProjectDetails(endpointAPI, orgID, project, apiToken)

		fmt.Println("2/4 - Getting Existing JIRA tickets")
		tickets := getJiraTickets(endpointAPI, orgID, project, apiToken)

		fmt.Println("3/4 - Getting vulns")
		vulnsPerPath := getVulnsWithoutTicket(endpointAPI, orgID, project, apiToken, severity, maturityFilter, priorityScoreThreshold, issueType, tickets)

		if len(vulnsPerPath) == 0 {
			fmt.Println("4/4 - No new JIRA ticket required")
		} else {
			fmt.Println("4/4 - Opening JIRA Tickets")
			numberIssueCreated, jiraResponse, notCreatedJiraIssues = openJiraTickets(endpointAPI, orgID, apiToken, jiraProjectID, jiraTicketType, assigneeID, labels, projectInfo, vulnsPerPath, priorityIsSeverity)
			if len(jiraResponse) == 0 {
				fmt.Println("Failure to create a ticket(s)")
			}
			fmt.Printf("-----Summary----- \n Number of tickets created: %d for project id: %s\n List of issueId for which the ticket could not be created: %s\n", numberIssueCreated, project, notCreatedJiraIssues)
		}
	}
}
