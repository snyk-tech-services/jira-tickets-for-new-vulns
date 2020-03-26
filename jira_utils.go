package main

import (
	"encoding/json"
	"fmt"
	"strings"

	bfconfluence "github.com/kentaro-m/blackfriday-confluence"
	"github.com/michael-go/go-jsn/jsn"
	bf "gopkg.in/russross/blackfriday.v2"
)

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

	// Sanitizing known issue where JIRA FW doesn't like this string....
	descriptionBody = strings.ReplaceAll(descriptionBody, "/etc/passwd", "")

	jiraTicket := &JiraIssue{
		Field{
			Summary:     projectInfo.K("name").String().Value + " - " + jsonVuln.K("title").String().Value,
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
