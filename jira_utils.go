package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	bfconfluence "github.com/kentaro-m/blackfriday-confluence"
	"github.com/michael-go/go-jsn/jsn"
	bf "gopkg.in/russross/blackfriday.v2"
)

type Tickets struct {
	Summary     string
	Description string
}

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
function writeLogFile
return date: string
input: map[string]interface{} logFile: details of the ticket to be written in the file
input: string filename: name of the file created in the main function
input: customDebug debug
Write the logFile in the file. Details are append to the file per project ID
***/
func writeLogFile(logFile map[string]interface{}, filename string, customDebug debug) {

	// write to file
	file, _ := json.MarshalIndent(logFile, "", "")

	// Find log file path
	_, b, _, _ := runtime.Caller(1)
	var d []string
	d = append(d, path.Join(path.Dir(b)))
	filenamePathArray := append(d, filename)
	// find os separator
	separator := string(os.PathSeparator)
	// build filename path
	filenamePath := strings.Join(filenamePathArray, separator)

	// If the file doesn't exist => exit, append to the file otherwise
	f, err := os.OpenFile(filenamePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not open file")
	}
	if _, err := f.Write(file); err != nil {
		customDebug.Debug("*** ERROR *** Could not open file")
	}
	if err := f.Close(); err != nil {
		customDebug.Debug("*** ERROR ***  Could not open file")
	}

	return
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
