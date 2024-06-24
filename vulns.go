package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/michael-go/go-jsn/jsn"
)

// IssuesFilter is the top level filter type of filtering Snyk response
type IssuesFilter struct {
	Filters Filter `json:"filters"`
}

type score struct {
	Min int `json:"min"`
	Max int `json:"max"`
}

type Priority struct {
	Score score `json:"score"`
}

// Filter allows to filter on severity, type, ignore or patched vuln
type Filter struct {
	// Severities      []string `json:"severities"`
	Severities      []string `json:"severityArray"`
	ExploitMaturity []string `json:"exploitMaturity,omitempty"`
	Priority        Priority `json:"priority"`
	Types           []string `json:"types"`
	Ignored         bool     `json:"ignored"`
	Patched         bool     `json:"patched"`
	isUpgradable    bool     `json:"isUpgradable"`
}

func getSeverity(flags flags) []string {

	var severity []string
	if len(flags.optionalFlags.severityArray) > 0 && len(flags.optionalFlags.severity) == 0 {

		// In this, low severity means get issues only with low severity,
		// medium means only medium and so on
		// if we want to use multiple severity, we have to pass comma separated values

		var severitiesArray []string = strings.Split(flags.optionalFlags.severityArray, ",")
		var severityFilter []string
		for _, severity := range severitiesArray {
			switch severity {
			case "critical":
				severityFilter = append(severityFilter, severity)
			case "high":
				severityFilter = append(severityFilter, severity)
			case "medium":
				severityFilter = append(severityFilter, severity)
			case "low":
				severityFilter = append(severityFilter, severity)
			case "":
			default:
				log.Fatalf("*** ERROR ***: %s is Unexpected severity threshold. Severity threshold must be one of {critical,high,medium,low}", severity)
			}
		}
		severity = severityFilter
	} else {
		// In the v1 api low severity means get all the issues up,
		// mediun means all but low and so on
		// this is not possible with v3.
		// to keep the logic of the tool
		// we create an array of severity
		// and loop on it to get all the issues
		switch flags.optionalFlags.severity {
		case "critical":
			severity = []string{"critical"}
		case "high":
			severity = []string{"critical", "high"}
		case "medium":
			severity = []string{"critical", "high", "medium"}
		case "low":
			severity = []string{"critical", "high", "medium", "low"}
		case "":
			severity = []string{"critical", "high", "medium", "low"}
		default:
			log.Fatalln("Unexpected severity threshold")
		}
	}

	return severity
}

func getVulnsWithoutTicket(flags flags, projectID string, maturityFilter []string, tickets map[string]string, customDebug debug) (map[string]interface{}, string, error) {

	body := IssuesFilter{
		Filter{
			Severities: []string{"high"},
			Types:      []string{"vuln", "license"},
			Priority:   Priority{score{Min: 0, Max: 1000}},
			Ignored:    false,
			Patched:    false,
		},
	}
	if flags.optionalFlags.issueType != "all" && flags.optionalFlags.issueType != "" {
		body.Filters.Types = []string{flags.optionalFlags.issueType}
	}
	body.Filters.Severities = getSeverity(flags)
	// switch flags.optionalFlags.severity {
	// case "critical":
	// 	body.Filters.Severities = []string{"critical"}
	// case "high":
	// 	body.Filters.Severities = []string{"critical", "high"}
	// case "medium":
	// 	body.Filters.Severities = []string{"critical", "high", "medium"}
	// case "low":
	// 	body.Filters.Severities = []string{"critical", "high", "medium", "low"}
	// default:
	// 	log.Fatalln("Unexpected severity threshold")
	// }

	if len(maturityFilter) > 0 {
		body.Filters.ExploitMaturity = maturityFilter
	}

	body.Filters.Priority.Score.Min = 0
	body.Filters.Priority.Score.Max = 1000
	if flags.optionalFlags.priorityScoreThreshold > 0 {
		body.Filters.Priority.Score.Min = flags.optionalFlags.priorityScoreThreshold
	}

	marshalledBody, err := json.Marshal(body)

	if err != nil {
		message := fmt.Sprintf(" *** ERROR *** IAC projects are not supported by this tool, skipping this project")
		writeErrorFile("getVulnsWithoutTicket", message, customDebug)
		customDebug.Debug(" *** ERROR *** IAC projects are not supported by this tool, skipping this project")
	}

	responseAggregatedData, err := makeSnykAPIRequest("POST", flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/project/"+projectID+"/aggregated-issues", flags.mandatoryFlags.apiToken, marshalledBody, customDebug)
	if err != nil {
		message := fmt.Sprintf("*** ERROR *** Could not get aggregated data from %s org %s project %s, skipping this project", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID)
		writeErrorFile("getVulnsWithoutTicket", message, customDebug)
		customDebug.Debugf("*** ERROR *** Could not get aggregated data from %s org %s project %s, skipping this project", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID)
		return nil, "", err
	}

	j, err := jsn.NewJson(responseAggregatedData)
	vulnsWithAllPaths := make(map[string]interface{})

	issueType := ""
	listOfIssues := j.K("issues").Array().Elements()
	if len(listOfIssues) > 0 {
		issueType = listOfIssues[0].K("issueType").String().Value
	}

	// IAC issues are of type configuration and are not supported atm
	if issueType == "configuration" {
		message := fmt.Sprintf(" *** WARN *** IAC projects are not supported, skipping project ID %s", projectID)
		writeErrorFile("getVulnsWithoutTicket", message, customDebug)
		customDebug.Debug(" *** WARN *** IAC projects are not supported, skipping")
		return vulnsWithAllPaths, "", err
	}

	// Code issue
	// the response from aggregated data is empty for code issues
	if len(listOfIssues) == 0 {
		snykCodeIssue, err := getSnykCodeIssueWithoutTickets(flags, projectID, tickets, customDebug)
		return snykCodeIssue, "", err
	}

	// Open source issue
	skippedIssues := ""
	vulnsWithAllPaths, skippedIssues, err = getSnykOpenSourceIssueWithoutTickets(flags, projectID, maturityFilter, tickets, customDebug, responseAggregatedData)

	return vulnsWithAllPaths, skippedIssues, err
}

/*
**
function getSnykOpenSourceIssueWithoutTickets
input flags mandatory and optionnal flags
input projectID string, the ID of the project we are get issues from
input tickets map[string]string, the list value pair ticket id, issue id which already have a ticket
input debug customDebug
input responseAggregatedData []byte, response from the aggregated data endpoint
return vulnsWithAllPaths map[string]interface{}, list of issues with all details and path
return skippedIssues string, list of issues that couldn't be created because there was a problem retrieving data from snyk
Create a list of issue details without tickets.

	Loop through the issues
		Get the path for each issue id
		add the path to the issue details

**
*/
func getSnykOpenSourceIssueWithoutTickets(flags flags, projectID string, maturityFilter []string, tickets map[string]string, customDebug debug, responseAggregatedData []byte) (map[string]interface{}, string, error) {
    

	issueType := flags.optionalFlags.issueType
    var issueTypeArray []string
    if issueType == "all" || issueType == "" {
        issueTypeArray = append(issueTypeArray, "vuln")
        issueTypeArray = append(issueTypeArray, "license")
    } else if issueType == "license" {
        issueTypeArray = append(issueTypeArray, "license")
    } else if issueType == "vuln" {
        issueTypeArray = append(issueTypeArray, "vuln")
    } else {
        var errorMessage = "*** ERROR *** %s is invalid issueType passed!!\n Please, Use all, vuln or license"
        err := fmt.Errorf(errorMessage, issueType)
        log.Fatalf(errorMessage, issueType)
        return nil, "", err
    }

	vulnsPerPath := make(map[string]interface{})
	vulnsWithAllPaths := make(map[string]interface{})

	j, err := jsn.NewJson(responseAggregatedData)
	if err != nil {
		message := fmt.Sprintf(" %s", err.Error())
		writeErrorFile("getSnykOpenSourceIssueWithoutTickets", message, customDebug)
		return nil, "", err
	}

	listOfIssues := j.K("issues").Array().Elements()

	issueSkipped := ""

	// for _, e := range listOfIssues {
	// 	if e.K("issueType").String().Value == "vuln" {
	// 		if len(e.K("id").String().Value) != 0 {
	// 			if _, found := tickets[e.K("id").String().Value]; !found {

	// 				var issueId = e.K("id").String().Value

	// 				bytes, err := json.Marshal(e)
	// 				if err != nil {
	// 					continue
	// 				}
	// 				json.Unmarshal(bytes, &vulnsPerPath)

	// 				ProjectIssuePathData, err := makeSnykAPIRequest("GET", flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/project/"+projectID+"/issue/"+issueId+"/paths", flags.mandatoryFlags.apiToken, nil, customDebug)
	// 				if err != nil {
	// 					log.Printf("*** ERROR *** Could not get paths data from %s org %s project %s issue %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
	// 					issueSkipped += "\nissue ID: " + issueId + " from project ID:" + projectID
	// 					message := fmt.Sprintf("*** ERROR *** Could not get paths data from %s org %s project %s issue %s skipped", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
	// 					writeErrorFile("getSnykOpenSourceIssueWithoutTickets", message, customDebug)
	// 					continue
	// 				}
	// 				ProjectIssuePathDataJson, er := jsn.NewJson(ProjectIssuePathData)
	// 				if er != nil {
	// 					log.Printf("*** ERROR *** Json creation failed\n")
	// 					issueSkipped += "\nissue ID: " + issueId + " from project ID:" + projectID
	// 					message := fmt.Sprintf("*** ERROR *** *** ERROR *** Json creation failed \n issue skipped %s org %s project %s issue %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
	// 					writeErrorFile("getSnykOpenSourceIssueWithoutTickets", message, customDebug)
	// 					continue
	// 				}
	// 				vulnsPerPath["from"] = ProjectIssuePathDataJson.K("paths")
	// 				marshalledvulnsPerPath, err := json.Marshal(vulnsPerPath)
	// 				vulnsWithAllPaths[issueId], err = jsn.NewJson(marshalledvulnsPerPath)
	// 				if er != nil {
	// 					log.Printf("*** ERROR *** vuln per path Json creation failed\n")
	// 					message := fmt.Sprintf("*** ERROR *** Json creation failed \n issue skipped %s org %s project %s issue %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
	// 					writeErrorFile("getSnykOpenSourceIssueWithoutTickets", message, customDebug)
	// 					issueSkipped += "\nissue ID: " + issueId + " from project ID:" + projectID
	// 					continue
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	// for _, e := range listOfIssues {
	// 	if e.K("issueType").String().Value == "license" {
	// 		if len(e.K("id").String().Value) != 0 {
	// 			if _, found := tickets[e.K("id").String().Value]; !found {
	// 				var issueId = e.K("id").String().Value
	// 				bytes, err := json.Marshal(e)
	// 				if err != nil {
	// 					continue
	// 				}
	// 				json.Unmarshal(bytes, &vulnsPerPath)

	// 				ProjectIssuePathData, err := makeSnykAPIRequest("GET", flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/project/"+projectID+"/issue/"+issueId+"/paths", flags.mandatoryFlags.apiToken, nil, customDebug)
	// 				if err != nil {
	// 					log.Printf("*** ERROR *** Could not get aggregated data from %s org %s project %s issue %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
	// 					issueSkipped += "\nissue ID: " + issueId + " from project ID:" + projectID
	// 					message := fmt.Sprintf("*** ERROR *** Could not get aggregated data from %s org %s project %s issue %s skipped", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
	// 					writeErrorFile("getSnykOpenSourceIssueWithoutTickets", message, customDebug)
	// 					continue
	// 				}

	// 				ProjectIssuePathDataJson, er := jsn.NewJson(ProjectIssuePathData)
	// 				if er != nil {
	// 					log.Printf("*** ERROR *** Json creation failed\n")
	// 					issueSkipped += "\nissue ID: " + issueId + " from project ID:" + projectID
	// 					message := fmt.Sprintf("*** ERROR *** Json creation failed \n issue skipped %s org %s project %s issue %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
	// 					writeErrorFile("getSnykOpenSourceIssueWithoutTickets", message, customDebug)
	// 					continue
	// 				}

	// 				vulnsPerPath["from"] = ProjectIssuePathDataJson.K("paths")
	// 				marshalledvulnsPerPath, err := json.Marshal(vulnsPerPath)
	// 				vulnsWithAllPaths[issueId], err = jsn.NewJson(marshalledvulnsPerPath)
	// 				if er != nil {
	// 					log.Printf("*** ERROR *** license per path Json creation failed\n")
	// 					issueSkipped += "\nissue ID: " + issueId + " from project ID:" + projectID
	// 					message := fmt.Sprintf("*** ERROR *** Json creation failed \n issue skipped %s org %s project %s issue %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
	// 					writeErrorFile("getSnykOpenSourceIssueWithoutTickets", message, customDebug)
	// 					continue
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	for _, e := range listOfIssues {
	    for _, issueType := range issueTypeArray {
		    if e.K("issueType").String().Value == issueType {
			    if len(e.K("id").String().Value) != 0 {
				    if _, found := tickets[e.K("id").String().Value]; !found {
					    var issueId = e.K("id").String().Value

					    bytes, err := json.Marshal(e)
					    if err != nil {
						    continue
					    }
					    json.Unmarshal(bytes, &vulnsPerPath)

					    ProjectIssuePathData, err := makeSnykAPIRequest("GET", flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/project/"+projectID+"/issue/"+issueId+"/paths", flags.mandatoryFlags.apiToken, nil, customDebug)
					    if err != nil {
						    log.Printf("*** ERROR *** Could not get paths data from %s org %s project %s issue %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
						    issueSkipped += "\nissue ID: " + issueId + " from project ID:" + projectID
						    continue
					    }
					    ProjectIssuePathDataJson, er := jsn.NewJson(ProjectIssuePathData)
					    if er != nil {
						    log.Printf("*** ERROR *** Json creation failed\n")
						    issueSkipped += "\nissue ID: " + issueId + " from project ID:" + projectID
						    continue
					    }
					    vulnsPerPath["from"] = ProjectIssuePathDataJson.K("paths")
					    marshalledvulnsPerPath, err := json.Marshal(vulnsPerPath)
					    vulnsWithAllPaths[issueId], err = jsn.NewJson(marshalledvulnsPerPath)
					    if er != nil {
						    log.Printf("*** ERROR *** Json creation failed\n")
						    issueSkipped += "\nissue ID: " + issueId + " from project ID:" + projectID
						    continue
					    }
					}
				}
			}
		}
	}

	return vulnsWithAllPaths, issueSkipped, nil
}

func createMaturityFilter(filtersArray []string) []string {

	var MaturityFilter []string

	for _, filter := range filtersArray {
		switch filter {
		case "no-data":
			MaturityFilter = append(MaturityFilter, filter)
		case "no-known-exploit":
			MaturityFilter = append(MaturityFilter, filter)
		case "proof-of-concept":
			MaturityFilter = append(MaturityFilter, filter)
		case "mature":
			MaturityFilter = append(MaturityFilter, filter)
		case "":
		default:
			log.Fatalf("*** ERROR ***: %s is not a valid maturity level. Levels are Must be one of [no-data,no-known-exploit,proof-of-concept,mature]", filter)
		}
	}
	return MaturityFilter
}

/*
**
function getSnykCodeIssueWithoutTickets
input flags mandatory and optionnal flags
input projectID string, the ID of the project we are get issues from
input tickets map[string]string, the list value pair ticket id, issue id which already have a ticket
input debug customDebug
return fullCodeIssueDetail map[string]interface{}, list of issue details without tickets
Create a list of issue details without tickets.

	Loop through the severity array to get the all issues IDs
	Loop through those ids the get the details
		The issue details doesn't give the title of the severity => adding it the the details
	Adding all the details to the list

**
*/
func getSnykCodeIssueWithoutTickets(flags flags, projectID string, tickets map[string]string, customDebug debug) (map[string]interface{}, error) {

	// In the v1 api low severity means get all the issues up,
	// mediun means all but low and so on
	// this is not possible with v3.
	// to keep the logic of the tool
	// we create an array of severity
	// and loop on it to get all the issues
	///////////////////////////////////////////
	// severity := []string{}
	// switch flags.optionalFlags.severity {
	// case "critical":
	// 	severity = []string{"critical"}
	// case "high":
	// 	severity = []string{"critical", "high"}
	// case "medium":
	// 	severity = []string{"critical", "high", "medium"}
	// case "low":
	// 	severity = []string{"critical", "high", "medium", "low"}
	// default:
	// 	message := fmt.Sprintf("*** ERROR *** Unexpected severity threshold ")
	// 	writeErrorFile("getSnykCodeIssueWithoutTickets", message, customDebug)
	// 	log.Fatalln("Unexpected severity threshold")
	// }
    var severity = getSeverity(flags)

	fullCodeIssueDetail := make(map[string]interface{})
	var errorMessage error

	// Doing this for test propose
	endpointAPI := "https://api.snyk.io"
	if IsTestRun() {
		endpointAPI = flags.mandatoryFlags.endpointAPI
	}

	for _, severityIndexValue := range severity {

		url := endpointAPI + "/rest/orgs/" + flags.mandatoryFlags.orgID + "/issues?project_id=" + projectID + "&version=2021-08-20~experimental"
		//if len(flags.optionalFlags.severity) > 0 {
		if len(severity) > 0 {
			url = endpointAPI + "/rest/orgs/" + flags.mandatoryFlags.orgID + "/issues?project_id=" + projectID + "&severity=" + severityIndexValue + "&version=2021-08-20~experimental"
		}

		for {
			// get the list of code issue for this project
			responseData, err := makeSnykAPIRequest("GET", url, flags.mandatoryFlags.apiToken, nil, customDebug)

			if err != nil {
				if (err.Error() != "Not found, Request failed") && (err.Error() != "Request failed with 50x") {
					log.Printf("*** ERROR ***** Could not get code issues list from %s org %s project %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID)
					errorMessage = err
					message := fmt.Sprintf("*** ERROR ***** Could not get code issues list from %s org %s project %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID)
					writeErrorFile("getSnykCodeIssueWithoutTickets", message, customDebug)
					break
				}
			}

			// loop through the issues and get the details
			jsonData, err := jsn.NewJson(responseData)

			issueDetail := make(map[string]interface{})

			for _, e := range jsonData.K("data").Array().Elements() {

				if len(e.K("id").String().Value) != 0 {
					if _, found := tickets[e.K("id").String().Value]; !found {

						// checking if the issue is ignored
						if e.K("attributes").K("ignored").Bool().Value == true {
							continue
						}

						id := e.K("id").String().Value

						url := endpointAPI + "/rest/orgs/" + flags.mandatoryFlags.orgID + "/issues/detail/code/" + id + "?project_id=" + projectID + "&version=2022-04-06~experimental"

						// get the details of this code issue id
						responseIssueDetail, err := makeSnykAPIRequest("GET", url, flags.mandatoryFlags.apiToken, nil, customDebug)
						if err != nil {
							log.Printf("*** ERROR *** Could not get code issues list from %s org %s project %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID)
							message := fmt.Sprintf("*** ERROR *** Could not get code issues list from %s org %s project %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID)
							writeErrorFile("getSnykCodeIssueWithoutTickets", message, customDebug)
							continue
						}

						jsonIssueDetail, er := jsn.NewJson(responseIssueDetail)
						if er != nil {
							log.Printf("*** ERROR *** Json creation failed\n")
							message := fmt.Sprintf("*** ERROR *** Json creation failed\n")
							writeErrorFile("getSnykCodeIssueWithoutTickets", message, customDebug)
							continue
						}

						bytes, err := json.Marshal(jsonIssueDetail)
						if err != nil {
							continue
						}
						json.Unmarshal(bytes, &issueDetail)

						if flags.optionalFlags.priorityScoreThreshold > 0 {
							if flags.optionalFlags.priorityScoreThreshold > jsonIssueDetail.K("data").K("attributes").K("priorityScore").Int().Value {
								customDebug.Debug(fmt.Sprintf("*** INFO *** Filtering out issue based on priority score priorityScoreThreshold=%d, issue priorityScore=%d", flags.optionalFlags.priorityScoreThreshold, jsonIssueDetail.K("data").K("attributes").K("priorityScore").Int().Value))
								continue
							}
						}

						issueDetail["title"] = e.K("attributes").K("title").String().Value

						marshalledjsonIssueDetail, err := json.Marshal(issueDetail)
						fullCodeIssueDetail[id], err = jsn.NewJson(marshalledjsonIssueDetail)
						if er != nil {
							log.Printf("*** ERROR *** Json creation failed\n")
							message := fmt.Sprintf("*** ERROR *** Json creation failed\n")
							writeErrorFile("getSnykCodeIssueWithoutTickets", message, customDebug)
							log.Fatalln(er)
						}
					}

				}
			}

			if len(jsonData.K("links").K("next").String().Value) > 0 {
				url = endpointAPI + "/rest" + jsonData.K("links").K("next").String().Value
			} else {
				break
			}
		}
	}

	return fullCodeIssueDetail, errorMessage
}
