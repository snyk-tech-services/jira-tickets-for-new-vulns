package main

import (
	"encoding/json"
	"log"

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
	Severities      []string `json:"severities"`
	ExploitMaturity []string `json:"exploitMaturity,omitempty"`
	Priority        Priority `json:"priority"`
	Types           []string `json:"types"`
	Ignored         bool     `json:"ignored"`
	Patched         bool     `json:"patched"`
}

func getVulnsWithoutTicket(flags flags, projectID string, maturityFilter []string, tickets map[string]string, customDebug debug) map[string]interface{} {

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
	switch flags.optionalFlags.severity {
	case "critical":
		body.Filters.Severities = []string{"critical"}
	case "high":
		body.Filters.Severities = []string{"critical", "high"}
	case "medium":
		body.Filters.Severities = []string{"critical", "high", "medium"}
	case "low":
		body.Filters.Severities = []string{"critical", "high", "medium", "low"}
	default:
		log.Fatalln("Unexpected severity threshold")
	}
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
		log.Fatalln(err)
	}

	responseAggregatedData, err := makeSnykAPIRequest("POST", flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/project/"+projectID+"/aggregated-issues", flags.mandatoryFlags.apiToken, marshalledBody, customDebug)
	if err != nil {
		log.Printf("*** ERROR *** Could not get aggregated data from %s org %s project %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID)
		log.Fatalln(err)
	}

	j, err := jsn.NewJson(responseAggregatedData)
	vulnsPerPath := make(map[string]interface{})
	vulnsWithAllPaths := make(map[string]interface{})

	for _, e := range j.K("issues").Array().Elements() {
		if len(e.K("id").String().Value) != 0 {
			if _, found := tickets[e.K("id").String().Value]; !found {
				var issueId = e.K("id").String().Value

				bytes, err := json.Marshal(e)
				if err != nil {
					log.Fatalln(err)
				}
				json.Unmarshal(bytes, &vulnsPerPath)

				ProjectIssuePathData, err := makeSnykAPIRequest("GET", flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/project/"+projectID+"/issue/"+issueId+"/paths", flags.mandatoryFlags.apiToken, nil, customDebug)
				if err != nil {
					log.Printf("*** ERROR *** Could not get aggregated data from %s org %s project %s issue %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
					log.Fatalln(err)
				}
				ProjectIssuePathDataJson, er := jsn.NewJson(ProjectIssuePathData)
				if er != nil {
					log.Printf("*** ERROR *** Json creation failed\n")
					log.Fatalln(er)
				}
				vulnsPerPath["from"] = ProjectIssuePathDataJson.K("paths")
				marshalledvulnsPerPath, err := json.Marshal(vulnsPerPath)
				vulnsWithAllPaths[issueId], err = jsn.NewJson(marshalledvulnsPerPath)
				if er != nil {
					log.Printf("*** ERROR *** Json creation failed\n")
					log.Fatalln(er)
				}
			}
		}
	}
	for _, e := range j.K("issues").K("licenses").Array().Elements() {
		if e.K("id").String().Value != "" {
			if _, found := tickets[e.K("id").String().Value]; !found {
				var issueId = e.K("id").String().Value

				bytes, err := json.Marshal(e)
				if err != nil {
					log.Fatalln(err)
				}
				json.Unmarshal(bytes, &vulnsPerPath)

				ProjectIssuePathData, err := makeSnykAPIRequest("GET", flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/project/"+projectID+"/issue/"+issueId+"/paths", flags.mandatoryFlags.apiToken, nil, customDebug)
				if err != nil {
					log.Printf("*** ERROR *** Could not get aggregated data from %s org %s project %s issue %s", flags.mandatoryFlags.endpointAPI, flags.mandatoryFlags.orgID, projectID, issueId)
					log.Fatalln(err)
				}
				ProjectIssuePathDataJson, er := jsn.NewJson(ProjectIssuePathData)
				if er != nil {
					log.Printf("*** ERROR *** Json creation failed\n")
					log.Fatalln(er)
				}
				vulnsPerPath["from"] = ProjectIssuePathDataJson.K("paths")
				marshalledvulnsPerPath, err := json.Marshal(vulnsPerPath)
				vulnsWithAllPaths[issueId], err = jsn.NewJson(marshalledvulnsPerPath)
				if er != nil {
					log.Printf("*** ERROR *** Json creation failed\n")
					log.Fatalln(er)
				}
			}
		}
	}
	return vulnsWithAllPaths
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
