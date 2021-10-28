package main

import (
	"fmt"
	"strings"
	"time"

	bfconfluence "github.com/kentaro-m/blackfriday-confluence"
	"github.com/michael-go/go-jsn/jsn"
	bf "gopkg.in/russross/blackfriday.v2"
)

/***
function getDate
return date: string
argument: none
return a string containing date and time
***/
func getDate() string {

	now := time.Now().Round(0)
	y := fmt.Sprint(now.Year()) + "_"
	m := fmt.Sprint(int(now.Month())) + "_"
	d := fmt.Sprint(now.Day()) + "_"
	h := fmt.Sprint(now.Hour()) + "_"
	min := fmt.Sprint(now.Minute()) + "_"
	s := fmt.Sprint(now.Second())

	return y + m + d + h + min + s
}

func formatJiraTicket(jsonVuln jsn.Json, projectInfo jsn.Json) *JiraIssue {

	issueData := jsonVuln.K("issueData")

	paths := "\n**Impacted Paths:**\n"

	for count, e := range jsonVuln.K("from").Array().Elements() {

		newPathArray := make([]string, len(e.Array().Elements()))

		for count_, j := range e.Array().Elements() {
			name := fmt.Sprintf("%s@%s", j.K("name").Stringify(), j.K("version").Stringify())

			newPathArray[count_] = name
		}

		paths += "- " + strings.Join(newPathArray, " => ") + "\n"

		if count > 10 {
			paths += "- ... [" + fmt.Sprintf("%d", len(jsonVuln.K("from").Array().Elements())-count) + " more paths](" + projectInfo.K("browseUrl").String().Value + ")"
			break
		}
	}

	snykBreadcrumbs := "\n[See this issue on Snyk](" + projectInfo.K("browseUrl").String().Value + ")\n"
	moreAboutThisIssue := "\n\n[More About this issue](" + issueData.K("url").String().Value + ")\n"
	vulnCvssScore := "\n cvssScore: " + fmt.Sprintf("%.2f", issueData.K("cvssScore").Float64().Value) + "\n"
	exploitMaturity := "\n exploitMaturity: " + issueData.K("exploitMaturity").String().Value + "\n"
	severity := "\n severity: " + issueData.K("severity").String().Value + "\n"
	pkgName := "\n pkgName: " + jsonVuln.K("pkgName").String().Value + "\n"
	pkgVersions := "\n pkgVersions: ["
	for count, e := range jsonVuln.K("pkgVersions").Array().Elements() {
		pkgVersions += fmt.Sprintf(e.String().Value)
		if count < len(jsonVuln.K("pkgVersions").Array().Elements())-1 {
			pkgVersions += ","
		}
	}
	pkgVersions += "]\n"

	descriptionFromIssue := ""

	if issueData.K("type").String().Value == "license" {
		descriptionFromIssue = `This dependency is infriguing your organization license policy. 
								Refer to the Reporting tab for possible instructions from your legal team.`
	}

	descriptionBody := markdownToConfluenceWiki("\n **** Issue details: ****\n" + "\r" + pkgName + "\r" + pkgVersions + "\r" + vulnCvssScore + "\r" + exploitMaturity + "\r" + severity + "\r" + paths + "\r" + snykBreadcrumbs + "\n" + descriptionFromIssue + "\n" + moreAboutThisIssue)
	descriptionBody = strings.ReplaceAll(descriptionBody, "{{", "{code}")
	descriptionBody = strings.ReplaceAll(descriptionBody, "}}", "{code}")

	// Sanitizing known issue where JIRA FW doesn't like this string....
	descriptionBody = strings.ReplaceAll(descriptionBody, "/etc/passwd", "")

	jiraTicket := &JiraIssue{
		Field{
			Summary:     projectInfo.K("name").String().Value + " - " + issueData.K("title").String().Value,
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
