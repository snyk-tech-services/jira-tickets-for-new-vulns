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

	bfconfluence "github.com/kentaro-m/blackfriday-confluence"
	"github.com/michael-go/go-jsn/jsn"
	bf "gopkg.in/russross/blackfriday.v2"
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

func openJiraTickets(endpointAPI string, orgID string, token string, jiraProjectID string, jiraTicketType string, projectInfo jsn.Json, vulnsForJira map[string]interface{}) {
	for _, vulnForJira := range vulnsForJira {
		jsonVuln, _ := jsn.NewJson(vulnForJira)
		vulnID := jsonVuln.K("id").String().Value
		jiraTicket := formatJiraTicket(jsonVuln, projectInfo)
		jiraTicket.Fields.Projects.Id = jiraProjectID
		jiraTicket.Fields.IssueTypes.Name = jiraTicketType

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

func formatJiraTicket(jsonVuln jsn.Json, projectInfo jsn.Json) *JiraIssue {

	paths := "\n**Impacted Paths:**\n"
	for count, e := range jsonVuln.K("from").Array().Elements() {
		var arr []string
		_ = json.Unmarshal([]byte(e.Stringify()), &arr)
		paths += "- " + strings.Join(arr, " => ") + "\n"

		if count > 10 {
			paths += "- ... [" + fmt.Sprintf("%d", len(jsonVuln.K("from").Array().Elements())-count) + " more paths](" + projectInfo.K("browseUrl").String().Value + ")"
			break
		}
	}
	fmt.Println(jsonVuln.Pretty())
	snykBreadcrumbs := "\n[See this issue on Snyk](" + projectInfo.K("browseUrl").String().Value + ")\n"
	moreAboutThisIssue := "\n\n[More About this issue](" + jsonVuln.K("url").String().Value + ")\n"
	descriptionFromIssue := jsonVuln.K("description").String().Value

	if descriptionFromIssue == "" && jsonVuln.K("type").String().Value == "license" {
		descriptionFromIssue = `This dependency is infriguing your organization license policy. 
								Refer to the Reporting tab for possible instructions from your legal team.`
	}

	descriptionBody := markdownToConfluenceWiki(paths + "\n" + snykBreadcrumbs + "\n" + descriptionFromIssue + "\n" + moreAboutThisIssue)
	descriptionBody = strings.ReplaceAll(descriptionBody, "{{", "{code}")
	descriptionBody = strings.ReplaceAll(descriptionBody, "}}", "{code}")

	// Sanitizing known issue where JIRA FW doesn't like us
	descriptionBody = strings.ReplaceAll(descriptionBody, "/etc/passwd", "")

	jiraTicket := &JiraIssue{
		Field{
			Summary:     projectInfo.K("name").String().Value + jsonVuln.K("title").String().Value,
			Description: descriptionBody,
		},
	}

	return jiraTicket

}

func markdownToConfluenceWiki(textToConvert string) string {
	renderer := &bfconfluence.Renderer{}
	extensions := bf.CommonExtensions
	md := bf.New(bf.WithRenderer(renderer), bf.WithExtensions(extensions))
	ast := md.Parse([]byte(textToConvert))
	output := renderer.Render(ast)
	return string(output)
}
