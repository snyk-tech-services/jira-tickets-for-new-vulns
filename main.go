package main

import (
	"bytes"
	"encoding/json"
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
	severityPtr := flag.String("severity", "high", "Your severity threshold")
	typePtr := flag.String("type", "all", "Your issue type (all|vuln|license)")
	flag.Parse()

	var orgID string = *orgIDPtr
	var projectID string = *projectIDPtr
	var endpointAPI string = *endpointAPIPtr
	var apiToken string = *apiTokenPtr
	var jiraProjectID string = *jiraProjectIDPtr
	var severity string = *severityPtr
	var issueType string = *typePtr

	fmt.Println("Getting Existing JIRA tickets")
	tickets := getJiraTicket(endpointAPI, orgID, projectID, apiToken)
	fmt.Println("Getting vulns")
	vulnsForJira := getVulnsWithoutTicket(endpointAPI, orgID, projectID, apiToken, severity, issueType, tickets)
	if len(vulnsForJira) == 0 {
		fmt.Println("No new JIRA ticket required")
	} else {
		openJiraTickets(endpointAPI, orgID, projectID, apiToken, jiraProjectID, vulnsForJira)
	}

}

func getJiraTicket(endpointAPI string, orgID string, projectID string, token string) map[string]string {
	request, _ := http.NewRequest("GET", endpointAPI+"/v1/org/"+orgID+"/project/"+projectID+"/jira-issues", nil)
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "token "+token)
	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	tickets, err := jsn.NewJson(responseData)
	fmt.Println(tickets)
	tickRefs := make(map[string]string)

	tickets.IterMap(func(k string, v jsn.Json) bool {
		tickRefs[k] = v.I(0).K("jiraIssue").K("key").String().Value

		return true
	})
	return tickRefs

}

func getVulnsWithoutTicket(endpointAPI string, orgID string, projectID string, token string, severity string, issueType string, tickets map[string]string) []interface{} {

	message := IssuesFilter{
		Filter{
			Severities: []string{"high"},
			Types:      []string{"vuln", "license"},
			Ignored:    false,
			Patched:    false,
		},
	}
	if issueType != "all" && issueType != "" {
		message.Filters.Types = []string{issueType}
	}
	switch severity {
	case "high":
		message.Filters.Severities = []string{"high"}
	case "medium":
		message.Filters.Severities = []string{"high", "medium"}
	case "low":
		message.Filters.Severities = []string{"high", "medium", "low"}
	default:
		log.Fatalln("Unexpected severity threshold")
	}
	fmt.Println(message)
	b, err := json.Marshal(message)

	if err != nil {
		log.Fatalln(err)
	}

	request, _ := http.NewRequest("POST", endpointAPI+"/v1/org/"+orgID+"/project/"+projectID+"/issues", bytes.NewBuffer(b))
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "token "+token)

	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	j, err := jsn.NewJson(responseData)
	var vulnsForJira []interface{}
	for _, e := range j.K("issues").K("vulnerabilities").Array().Elements() {
		if _, found := tickets[e.K("id").String().Value]; !found {
			// fmt.Println(e.Pretty())
			//fmt.Println(v)
			vulnsForJira = append(vulnsForJira, e)
		}

	}
	for _, e := range j.K("issues").K("licenses").Array().Elements() {
		if _, found := tickets[e.K("id").String().Value]; !found {
			// fmt.Println(e.Pretty())
			//fmt.Println(v)
			vulnsForJira = append(vulnsForJira, e)
		}

	}
	return vulnsForJira

}

func openJiraTickets(endpointAPI string, orgID string, projectID string, token string, jiraProjectID string, vulnsForJira []interface{}) {

	for _, e := range vulnsForJira {
		j, _ := jsn.NewJson(e)
		jiraTicket := &JiraIssue{
			Field{
				Summary:     j.K("title").String().Value,
				Description: j.K("description").String().Value,
			},
		}
		jiraTicket.Fields.Projects.Id = jiraProjectID
		jiraTicket.Fields.IssueTypes.Name = "Bug"

		ticket, err := json.Marshal(jiraTicket)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(string(ticket))
		request, _ := http.NewRequest("POST", endpointAPI+"/v1/org/"+orgID+"/project/"+projectID+"/issue/"+j.K("id").String().Value+"/jira-issue", bytes.NewBuffer(ticket))
		request.Header.Add("Content-Type", "application/json")
		request.Header.Add("Authorization", "token "+token)

		client := &http.Client{}
		response, err := client.Do(request)

		if err != nil {
			fmt.Print(err.Error())
			os.Exit(1)
		}

		responseData, err := ioutil.ReadAll(response.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(responseData))
	}
}
