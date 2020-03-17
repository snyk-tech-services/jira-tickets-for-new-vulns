package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/michael-go/go-jsn/jsn"
)

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

	tickRefs := make(map[string]string)

	tickets.IterMap(func(k string, v jsn.Json) bool {
		tickRefs[k] = v.I(0).K("jiraIssue").K("key").String().Value

		return true
	})
	return tickRefs

}

func openJiraTickets(endpointAPI string, orgID string, token string, jiraProjectID string, projectInfo jsn.Json, vulnsForJira map[string]interface{}) {
	for _, vulnForJira := range vulnsForJira {
		jsonVuln, _ := jsn.NewJson(vulnForJira)
		vulnID := jsonVuln.K("id").String().Value
		jiraTicket := formatJiraTicket(jsonVuln, jiraProjectID, projectInfo)

		ticket, err := json.Marshal(jiraTicket)
		if err != nil {
			log.Fatalln(err)
		}

		request, _ := http.NewRequest("POST", endpointAPI+"/v1/org/"+orgID+"/project/"+projectInfo.K("id").String().Value+"/issue/"+vulnID+"/jira-issue", bytes.NewBuffer(ticket))
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

func formatJiraTicket(jsonVuln jsn.Json, jiraProjectID string, projectInfo jsn.Json) *JiraIssue {

	paths := "\nImpacted Paths:\n"
	for _, e := range jsonVuln.K("from").Array().Elements() {
		var arr []string
		_ = json.Unmarshal([]byte(e.Stringify()), &arr)
		paths += strings.Join(arr, "->") + "\n"
	}

	jiraTicket := &JiraIssue{
		Field{
			Summary:     projectInfo.K("name").String().Value + jsonVuln.K("title").String().Value,
			Description: paths + "\n" + jsonVuln.K("description").String().Value,
		},
	}
	jiraTicket.Fields.Projects.Id = jiraProjectID
	jiraTicket.Fields.IssueTypes.Name = "Task"

	return jiraTicket

}
