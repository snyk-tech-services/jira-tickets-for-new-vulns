package main

import (
	"encoding/json"
	"fmt"
	"strings"

	bfconfluence "github.com/kentaro-m/blackfriday-confluence"
	"github.com/michael-go/go-jsn/jsn"
	bf "gopkg.in/russross/blackfriday.v2"
)

const JiraPrefix = "jiraValue-"
const JiraMultiSelect = "MultiSelect"
const JiraMultiGroupPicker = "MultiGroupPicker"
const JiraLabels = "Labels"

type JiraIssueForTicket struct {
	Id  string `json:Id,omitempty"`
	Key string `json:Key,omitempty"`
}

type JiraDetailForTicket struct {
	JiraIssue *JiraIssueForTicket `json:jiraIssue,omitempty"`
	IssueId   string              `json:IssueId,omitempty"`
}

type Tickets struct {
	Summary         string               `json:Summary`
	Description     string               `json:Description`
	JiraIssueDetail *JiraDetailForTicket `json:JiraIssueDetail,omitempty"`
}

type LogFile struct {
	Projects map[string]interface{} `json:projects`
}

func getJiraTicketId(responseData []byte) *JiraDetailForTicket {

	var responseDataUnMarshal map[string][]interface{}
	var jiraIssueDetails *JiraDetailForTicket
	json.Unmarshal(responseData, &responseDataUnMarshal)

	for index, element := range responseDataUnMarshal {

		for _, jiraIssueEl := range element {
			jsonJiraIssueEl, _ := jsn.NewJson(jiraIssueEl)
			jiraIssueForTicket := &JiraIssueForTicket{
				Id:  jsonJiraIssueEl.K("jiraIssue").K("id").String().Value,
				Key: jsonJiraIssueEl.K("jiraIssue").K("key").String().Value,
			}

			jiraIssueDetails = &JiraDetailForTicket{
				JiraIssue: jiraIssueForTicket,
				IssueId:   index,
			}
		}
	}

	return jiraIssueDetails
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

func formatCodeJiraTicket(jsonVuln jsn.Json, projectInfo jsn.Json) *JiraIssue {

	issueData := jsonVuln.K("data")

	var priorityScoreFactorsArray []string
	for _, e := range issueData.K("attributes").K("priorityScoreFactors").Array().Elements() {
		priorityScoreFactorsArray = append(priorityScoreFactorsArray, fmt.Sprintf(e.String().Value))
	}

	priorityScoreFactors := "\n PriorityScoreFactors: \n  - "
	priorityScoreFactors += strings.Join(priorityScoreFactorsArray, " \n  - ")

	files := "\r\n ***Impacted file:***\n\r"
	files += "   " + issueData.K("attributes").K("primaryFilePath").String().Value + "\n  - startLine: "
	files += fmt.Sprint(issueData.K("attributes").K("primaryRegion").K("startLine").Int().Value) + "\n  - startColumn: "
	files += fmt.Sprint(issueData.K("attributes").K("primaryRegion").K("startColumn").Int().Value) + "\n  - endLine: "
	files += fmt.Sprint(issueData.K("attributes").K("primaryRegion").K("endLine").Int().Value) + "\n  - endColumn: "
	files += fmt.Sprint(issueData.K("attributes").K("primaryRegion").K("endColumn").Int().Value) + "\n"

	snykBreadcrumbs := "\n[See this issue on Snyk](" + projectInfo.K("browseUrl").String().Value + ")\n"

	issueDetails := []string{"\r\n **** Issue details: ****\n\r",
		"\n Title: ", jsonVuln.K("title").String().Value,
		"\n Summary: ", issueData.K("attributes").K("title").String().Value,
		"\n Severity: ", issueData.K("attributes").K("severity").String().Value,
		"\n PriorityScore: ", fmt.Sprintf("%d", issueData.K("attributes").K("priorityScore").Int().Value),
		priorityScoreFactors,
		files,
		snykBreadcrumbs,
	}

	descriptionBody := markdownToConfluenceWiki(strings.Join(issueDetails, " "))
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

/***
function addMandatoryFieldToTicket
input []byte ticket, ticket previously created without any mandatory fields
input map[string]interface{} customMandatoryField, the new mandatory field
input debug
return []byte ticket
Loop through the mandatory fields
create a list of key value pair for each
and add it to the ticket
***/
func addMandatoryFieldToTicket(ticket []byte, customMandatoryField map[string]interface{}, customDebug debug) []byte {

	unmarshalledTicket := make(map[string]interface{})
	fields := make(map[string]interface{})
	newTicket := make(map[string]interface{})

	err := json.Unmarshal(ticket, &unmarshalledTicket)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not unMarshalled ticket, mandatory fields will no the added ", err)
	}

	fieldFromTicket := unmarshalledTicket["fields"]

	marshalledFieldFromTicket, _ := json.Marshal(fieldFromTicket)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not marshall ticket fields, mandatory fields will no the added ", err)
	}

	err = json.Unmarshal(marshalledFieldFromTicket, &fields)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not unMarshalled ticket fields, mandatory fields will no the added ", err)
	}

	for i, s := range customMandatoryField {

		value, ok := s.(map[string]interface{})
		if ok {
			v, ok := value["value"].(string)
			if ok {
				if strings.HasPrefix(v, JiraPrefix) {
					s = supportJiraFormats(v, customDebug)
				}
			}
		} else {
			customDebug.Debug(fmt.Sprintf("*** ERROR *** Assertion error expected map[string]interface{} but got type %T ", s))
		}

		fields[i] = s
	}

	newTicket["fields"] = fields

	newMarchalledTicket, err := json.Marshal(newTicket)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not Marshalled new ticket, mandatory fields will no the added ", err)
	}

	return newMarchalledTicket
}

/***
function supportJiraFormats
input interface{} v, previous custom value
input debug
return interface{}
replace any custom values which start with "jiraValue-" with the proper formatting for jira
Usage: customfield_10601:
      value: jira-MultiGroupPicker-Value1,Value2
https://developer.atlassian.com/server/jira/platform/jira-rest-api-example-create-issue-7897248/
***/
func supportJiraFormats(v string, customDebug debug) (result interface{}) {

	valueSplit := strings.Split(v, "-")

	switch valueSplit[1] {
	case JiraMultiSelect:
		list := make([]map[string]string, 0)
		// add each selection to the collection
		for _, x := range strings.Split(valueSplit[2], ",") {
			data := make(map[string]string)
			data["value"] = x

			list = append(list, data)
		}

		result = list
	case JiraMultiGroupPicker:
		list := make([]map[string]string, 0)
		// add each selection to the collection
		for _, x := range strings.Split(valueSplit[2], ",") {
			data := make(map[string]string)
			data["name"] = x

			list = append(list, data)
		}

		result = list
	case JiraLabels:
		list := []string{}
		for _, x := range strings.Split(valueSplit[2], ",") {
			list = append(list, x)
		}

		result = list
	}

	customDebug.Debug(fmt.Sprintf("*** INFO *** Custom field value '%s' replaced with '%s' ", v, result))

	return result
}
