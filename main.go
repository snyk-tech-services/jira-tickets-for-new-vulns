package main

import (
	"flag"
	"fmt"
	"os"
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
	typePtr := flag.String("type", "all", "Optional. Your issue type (all|vuln|license)")
	flag.Parse()

	var orgID string = *orgIDPtr
	var projectID string = *projectIDPtr
	var endpointAPI string = *endpointAPIPtr
	var apiToken string = *apiTokenPtr
	var jiraProjectID string = *jiraProjectIDPtr
	var jiraTicketType string = *jiraTicketTypePtr
	var severity string = *severityPtr
	var issueType string = *typePtr

	if len(orgID) == 0 || len(apiToken) == 0 || len(jiraProjectID) == 0 {
		fmt.Println("Missing argument(s)")
		flag.PrintDefaults()
		os.Exit(1)
	}

	projectIDs := make([]string, 0)

	if len(projectID) == 0 {
		fmt.Println("Project ID not specified - importing all projects")

		projects := getOrgProjects(endpointAPI, orgID, apiToken)

		for _, p := range projects.K("projects").Array().Elements() {
			projectIDs = append(projectIDs, p.K("id").String().Value)
		}
	} else {
		projectIDs = append(projectIDs, projectID)
	}

	for _, project := range projectIDs {
		fmt.Println("1/4 - Retrieving Project", project)
		projectInfo := getProjectDetails(endpointAPI, orgID, project, apiToken)

		fmt.Println("2/4 - Getting Existing JIRA tickets")
		tickets := getJiraTickets(endpointAPI, orgID, project, apiToken)

		fmt.Println("3/4 - Getting vulns")
		vulnsPerPath := getVulnsWithoutTicket(endpointAPI, orgID, project, apiToken, severity, issueType, tickets)
		vulnsForJira := consolidateAllPathsIntoSingleVuln(vulnsPerPath)

		if len(vulnsForJira) == 0 {
			fmt.Println("4/4 - No new JIRA ticket required")
		} else {
			fmt.Println("4/4 - Opening JIRA Tickets")
			jiraResponse := openJiraTickets(endpointAPI, orgID, apiToken, jiraProjectID, jiraTicketType, projectInfo, vulnsForJira)
			fmt.Println(jiraResponse)
		}

	}

}
