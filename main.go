package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/michael-go/go-jsn/jsn"
)

type IssuesFilter struct {
	Filters Filter `json:"filters"`
}
type Filter struct {
	Severities []string `json:"severities"`
	Types      []string `json:"types"`
	Ignored    bool     `json:"ignored"`
	Patched    bool     `json:"patched"`
}

type JiraIssue struct {
	Fields Field `json:"fields"`
}
type Field struct {
	Projects    Project   `json:"project"`
	Summary     string    `json:"summary"`
	Description string    `json:"description"`
	IssueTypes  IssueType `json:"issuetype"`
}

type Project struct {
	Id string `json:"id"`
}

type IssueType struct {
	Name string `json:"name"`
}

func main() {
	orgIDPtr := flag.String("orgID", "", "Your Org ID")
	projectIDPtr := flag.String("projectID", "", "Your Project ID")
	endpointAPIPtr := flag.String("api", "https://snyk.io/api", "Your API endpoint")
	apiTokenPtr := flag.String("token", "", "Your API token")
	jiraProjectIDPtr := flag.String("jiraProjectID", "", "Your JIRA projectID")
	jiraTicketTypePtr := flag.String("jiraTicketType", "Bug", "Chosen JIRA ticket type - Default Bug")
	severityPtr := flag.String("severity", "low", "Your severity threshold - Default low")
	typePtr := flag.String("type", "all", "Your issue type (all|vuln|license) - Default all")
	flag.Parse()

	var orgID string = *orgIDPtr
	var projectID string = *projectIDPtr
	var endpointAPI string = *endpointAPIPtr
	var apiToken string = *apiTokenPtr
	var jiraProjectID string = *jiraProjectIDPtr
	var jiraTicketType string = *jiraTicketTypePtr
	var severity string = *severityPtr
	var issueType string = *typePtr

	if len(orgID) == 0 || len(projectID) == 0 || len(apiToken) == 0 || len(jiraProjectID) == 0 {
		fmt.Println("Missing argument(s)")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Println("Retrieving Project")
	projectInfo := getProjectDetails(endpointAPI, orgID, projectID, apiToken)

	fmt.Println("Getting Existing JIRA tickets")
	tickets := getJiraTicket(endpointAPI, orgID, projectID, apiToken)

	//fmt.Println(tickets)
	fmt.Println("Getting vulns")
	vulnsPerPath := getVulnsWithoutTicket(endpointAPI, orgID, projectID, apiToken, severity, issueType, tickets)
	vulnsForJira := consolidatePathsIntoVulnsForJira(vulnsPerPath)
	//fmt.Println(vulnsForJira)
	if len(vulnsForJira) == 0 {
		fmt.Println("No new JIRA ticket required")
	} else {
		fmt.Println("Opening JIRA Tickets")
		openJiraTickets(endpointAPI, orgID, apiToken, jiraProjectID, jiraTicketType, projectInfo, vulnsForJira)
	}

}

func getProjectDetails(endpointAPI string, orgID string, projectID string, token string) jsn.Json {
	request, _ := http.NewRequest("GET", endpointAPI+"/v1/org/"+orgID+"/project/"+projectID, nil)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "token "+token)
	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}
	if response.StatusCode == 404 {
		fmt.Println("Project not found")
		os.Exit(1)
	}
	if response.StatusCode < 400 {
		fmt.Printf("Unexpected response %d", response.StatusCode)
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	project, err := jsn.NewJson(responseData)

	return project

}
