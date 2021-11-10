package main

import (
	"bufio"
	"fmt"
	"os"
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

/***
function findProjectId
return found: bool
return error
input: projectId string
input: filename path string
return true if the project already exist in the file
***/
func findProjectId(projectId string, filename string, customDebug debug) (bool, error) {

	f, err := os.Open(filename)
	if err != nil {
		customDebug.Debugf("*** ERROR *** couldn't find log file")
		return false, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		if strings.Contains(scanner.Text(), projectId) {
			return true, nil
		}
	}
	return false, err
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
		paths += "\r"
	}

	var pkgVersionsArray []string
	// jsonVuln.K("pkgVersions").Array().Elements() is []jsn.json
	// Need to build a []string to use Join()
	for _, e := range jsonVuln.K("pkgVersions").Array().Elements() {
		pkgVersionsArray = append(pkgVersionsArray, fmt.Sprintf(e.String().Value))
	}

	snykBreadcrumbs := "\n[See this issue on Snyk](" + projectInfo.K("browseUrl").String().Value + ")\n"
	moreAboutThisIssue := "\n\n[More About this issue](" + issueData.K("url").String().Value + ")\n"

	pkgVersions := "\n pkgVersions: "
	pkgVersions += strings.Join(pkgVersionsArray, ",")
	pkgVersions += "]\n\r"

	descriptionFromIssue := ""

	if issueData.K("type").String().Value == "license" {
		descriptionFromIssue = `This dependency is infriguing your organization license policy. 
								Refer to the Reporting tab for possible instructions from your legal team.`
	}

	issueDetails := []string{"\r\n **** Issue details: ****\n\r",
		"\n cvssScore: ", fmt.Sprintf("%.2f", issueData.K("cvssScore").Float64().Value),
		"\n exploitMaturity: ", issueData.K("exploitMaturity").String().Value,
		"\n severity: ", issueData.K("severity").String().Value,
		pkgVersions,
		paths,
		snykBreadcrumbs,
		descriptionFromIssue,
		moreAboutThisIssue,
	}

	descriptionBody := markdownToConfluenceWiki(strings.Join(issueDetails, " "))
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
