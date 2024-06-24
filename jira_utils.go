package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"log"
	"strings"

	bfconfluence "github.com/kentaro-m/blackfriday-confluence"
	"github.com/michael-go/go-jsn/jsn"
	bf "gopkg.in/russross/blackfriday.v2"
)

const JiraPrefix = "jiraValue-"
const JiraMultiSelect = "MultiSelect"
const JiraMultiGroupPicker = "MultiGroupPicker"
const JiraLabels = "Labels"
const JiraSimpleField = "simpleField"

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

func formatJiraTicket(jsonVuln jsn.Json, projectInfo jsn.Json, flags flags) *JiraIssue {

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

	snykBreadcrumbs := "\n\n[See this issue on Snyk](" + projectInfo.K("browseUrl").String().Value + ")\n"
	moreAboutThisIssue := "\n\n[More About this issue](" + issueData.K("url").String().Value + ")\n"

	pkgVersions := "\n pkgVersions: "
	pkgVersions += "[" + strings.Join(pkgVersionsArray, ", ")
	pkgVersions += "]\n\r"

	descriptionFromIssue := ""

	if issueData.K("type").String().Value == "license" {
		descriptionFromIssue = `This dependency is infringing your organization license policy.
								Refer to the Reporting tab for possible instructions from your legal team.`
	}

	var identifiers []string
	var cveIdentifiers []string
	issueData.K("identifiers").IterMap(
		func(k string, v jsn.Json) bool {
			for _, value := range v.Array().Elements() {
				identifiers = append(identifiers, value.String().Value)
				if k == "CVE" {
					cveIdentifiers = append(cveIdentifiers, value.String().Value)
				}
			}
			return true // false to break
		})

	if len(identifiers) == 0 {
		identifiers = append(identifiers, "N/A")
	} else {
		sort.Strings(identifiers)
	}
	issueDetails := []string{"\r\n** Issue details: **\n\r",
		"\n cvssScore: ", fmt.Sprintf("%.2f", issueData.K("cvssScore").Float64().Value),
		"\n identifiers: ", strings.Join(identifiers, ", "),
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

	// Build Summary
	summary := projectInfo.K("name").String().Value + " - " + issueData.K("title").String().Value
	if flags.optionalFlags.cveInTitle == true && len(cveIdentifiers) > 0 {
		summary = fmt.Sprintf("%s - %s", summary, strings.Join(cveIdentifiers, ", "))
	}

	jiraTicket := &JiraIssue{
		Field{
			Summary:     summary,
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

func formatCodeJiraTicket(jsonVuln jsn.Json, projectInfo jsn.Json, flags flags) *JiraIssue {

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
	summary := projectInfo.K("name").String().Value + " - " + jsonVuln.K("title").String().Value
	// TODO: add CVE in title once API sends it
	jiraTicket := &JiraIssue{
		Field{
			Summary:     summary,
			Description: descriptionBody,
		},
	}

	return jiraTicket
}

/*
**
function addMandatoryFieldToTicket
input []byte ticket, ticket previously created without any mandatory fields
input map[string]interface{} customMandatoryField, the new mandatory field
input debug
return []byte ticket
Add the mandatory fields extracted during setup to the ticket
**
*/
// func addMandatoryFieldToTicket(ticket []byte, customMandatoryField map[string]interface{}, customDebug debug) []byte {

// 	unmarshalledTicket := make(map[string]interface{})
// 	fields := make(map[string]interface{})
// 	newTicket := make(map[string]interface{})

// 	err := json.Unmarshal(ticket, &unmarshalledTicket)
// 	if err != nil {
// 		message := fmt.Sprintf("*** ERROR *** Could not unMarshalled ticket, mandatory fields will no the added %s", err.Error())
// 		writeErrorFile("addMandatoryFieldToTicket", message, customDebug)
// 		customDebug.Debug("*** ERROR *** Could not unMarshalled ticket, mandatory fields will no the added ", err)
// 	}

// 	fieldFromTicket := unmarshalledTicket["fields"]

// 	marshalledFieldFromTicket, _ := json.Marshal(fieldFromTicket)
// 	if err != nil {
// 		message := fmt.Sprintf("*** ERROR *** Could not parse Jira fields config, mandatory fields will no the added %s", err.Error())
// 		writeErrorFile("addMandatoryFieldToTicket", message, customDebug)
// 		customDebug.Debug(message, err)
// 	}

// 	err = json.Unmarshal(marshalledFieldFromTicket, &fields)
// 	if err != nil {
// 		customDebug.Debug("*** ERROR *** Could not Jira fields config, mandatory fields will no the added ", err)
// 	}
    
	
// 	for i, s := range customMandatoryField {

// 		value, ok := s.(map[string]interface{})
// 		if ok {
// 			v, ok := value["value"].(string)
// 			if ok {
// 				if strings.HasPrefix(v, JiraPrefix) {
// 					s, _ = supportJiraFormats(v, customDebug)
// 				}
// 			}
// 		} else {
// 			customDebug.Debug(fmt.Sprintf("*** ERROR *** Expected mandatory Jira fields configuration to be in format map[string]interface{}, received type: %T for field %s ", s, i))
// 			message := fmt.Sprintf("*** ERROR *** Expected mandatory Jira fields configuration to be in format map[string]interface{}, received type: %T for field %s ", s, i)
// 			writeErrorFile("addMandatoryFieldToTicket", message, customDebug)
// 		}

// 		fields[i] = s
// 	}

// 	newTicket["fields"] = fields

// 	newMarshalledTicket, err := json.Marshal(newTicket)
// 	if err != nil {
// 		customDebug.Debug("*** ERROR *** Invalid JSON, mandatory Jira fields will be skipped. ERROR:", err)
// 		message := fmt.Sprintf("*** ERROR *** Invalid JSON, mandatory Jira fields will be skipped. ERROR: %s", err.Error())
// 		writeErrorFile("addMandatoryFieldToTicket", message, customDebug)
// 	}

// 	return newMarshalledTicket
// }

func addMandatoryFieldToTicket(ticket []byte, customMandatoryField map[string]interface{}, customDebug debug) []byte {

    unmarshalledTicket := make(map[string]interface{})
    fields := make(map[string]interface{})
    newTicket := make(map[string]interface{})

    err := json.Unmarshal(ticket, &unmarshalledTicket)
    if err != nil {
        message := fmt.Sprintf("*** ERROR *** Could not unMarshal ticket, mandatory fields will not be added %s", err.Error())
        writeErrorFile("addMandatoryFieldToTicket", message, customDebug)
        customDebug.Debug("*** ERROR *** Could not unMarshal ticket, mandatory fields will not be added ", err)
    }

    fieldFromTicket, ok := unmarshalledTicket["fields"].(map[string]interface{})
    if !ok {
        message := "*** ERROR *** Could not parse Jira fields config, mandatory fields will not be added"
        writeErrorFile("addMandatoryFieldToTicket", message, customDebug)
        customDebug.Debug(message)
        return ticket
    }

    for key, value := range fieldFromTicket {
        fields[key] = value
    }
    
	log.Println("customMandatoryField %s", customMandatoryField)
	
    for i, s := range customMandatoryField {
        switch v := s.(type) {
        case string:
            fields[i] = v
        case map[string]interface{}:
            fieldValue, ok := v["value"].(string)
            if ok && strings.HasPrefix(fieldValue, JiraPrefix) {
                newValue, err := supportJiraFormats(fieldValue, customDebug)
                if err != nil {
                    message := fmt.Sprintf("*** ERROR *** Error while extracting the mandatory Jira fields configuration for field %s: %s", i, err)
                    writeErrorFile("addMandatoryFieldToTicket", message, customDebug)
                    customDebug.Debug(message)
                    continue
                }
                fields[i] = newValue
            } else {
                fields[i] = s
            }
        default:
            message := fmt.Sprintf("*** ERROR *** Unexpected type for field %s: %T", i, s)
            writeErrorFile("addMandatoryFieldToTicket", message, customDebug)
            customDebug.Debug(message)
            continue
        }
    }

    newTicket["fields"] = fields

    newMarshalledTicket, err := json.Marshal(newTicket)
    if err != nil {
        message := fmt.Sprintf("*** ERROR *** Invalid JSON, mandatory Jira fields will be skipped. ERROR: %s", err.Error())
        writeErrorFile("addMandatoryFieldToTicket", message, customDebug)
        customDebug.Debug(message)
        return ticket
    }

    return newMarshalledTicket
}

/*
**
function supportJiraFormats
input interface{} v, previous custom value
input debug
return interface{}
replace any custom values which start with "jiraValue-" with the proper formatting for jira
Usage: customfield_10601:

	value: jira-MultiGroupPicker-Value1,Value2

https://developer.atlassian.com/server/jira/platform/jira-rest-api-example-create-issue-7897248/
**
*/
func supportJiraFormats(v string, customDebug debug) (result interface{}, err error) {

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

		if len(list) == 0 {
			return nil, errors.New("Custom field format JiraMultiSelect not recognized, please check the config file.")
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

		if len(list) == 0 {
			return nil, errors.New("Custom field format JiraMultiGroupPicker not recognized, please check the config file.")
		}

		result = list
	case JiraLabels:
		list := []string{}
		for _, x := range strings.Split(valueSplit[2], ",") {
			list = append(list, x)
		}

		if len(list) == 0 {
			return nil, errors.New("Custom field format JiraLabels not recognized, please check the config file.")
		}

		result = list

	case JiraSimpleField:

		if len(valueSplit[2]) == 0 {
			return nil, errors.New("Custom field format JiraSimpleField not recognized, please check the config file.")
		}

		result = valueSplit[2]

	default:
		return nil, errors.New("Custom field format not recognized, please check the config file.")
	}

	if customDebug.PrintDebug {
		customDebug.Debug(fmt.Sprintf("*** INFO *** Custom field value '%s' replaced with '%s' ", v, result))
	}

	return result, nil
}
