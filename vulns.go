package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/michael-go/go-jsn/jsn"
	"github.com/tidwall/sjson"
)

func getVulnsWithoutTicket(endpointAPI string, orgID string, projectID string, token string, severity string, issueType string, tickets map[string]string) []interface{} {

	message := IssuesFilter{
		Filter{
			Severities: []string{"high"},
			Types:      []string{"vuln", "license"},
			Ignored:    false,
			Patched:    false,
		},
	}
	if issueType != "all" && issueType != "" {
		message.Filters.Types = []string{issueType}
	}
	switch severity {
	case "high":
		message.Filters.Severities = []string{"high"}
	case "medium":
		message.Filters.Severities = []string{"high", "medium"}
	case "low":
		message.Filters.Severities = []string{"high", "medium", "low"}
	default:
		log.Fatalln("Unexpected severity threshold")
	}
	//fmt.Println(message)
	b, err := json.Marshal(message)

	if err != nil {
		log.Fatalln(err)
	}

	request, _ := http.NewRequest("POST", endpointAPI+"/v1/org/"+orgID+"/project/"+projectID+"/issues", bytes.NewBuffer(b))
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

	j, err := jsn.NewJson(responseData)
	var vulnsPerPath []interface{}
	for _, e := range j.K("issues").K("vulnerabilities").Array().Elements() {

		if _, found := tickets[e.K("id").String().Value]; !found {
			vulnsPerPath = append(vulnsPerPath, e)
		}

	}
	for _, e := range j.K("issues").K("licenses").Array().Elements() {

		if _, found := tickets[e.K("id").String().Value]; !found {
			vulnsPerPath = append(vulnsPerPath, e)
		}

	}

	return vulnsPerPath

}

func consolidatePathsIntoVulnsForJira(vulnsPerPath []interface{}) map[string]interface{} {
	var vulnsForJira map[string]interface{}
	vulnsForJira = make(map[string]interface{})
	for _, vulnPerPath := range vulnsPerPath {
		vuln := vulnPerPath
		vulnJSON, _ := jsn.NewJson(vuln)

		if _, found := vulnsForJira[vulnJSON.K("id").String().Value]; !found {

			var vulnJSONPaths [][]string
			var vulnJSONPath []string
			for _, value := range vulnJSON.K("from").Array().Elements() {
				vulnJSONPath = append(vulnJSONPath, value.Stringify())
			}
			vulnJSONPaths = append(vulnJSONPaths, vulnJSONPath)
			vuln, _ = sjson.Set(vulnJSON.Stringify(), "from", vulnJSONPaths)

		} else {
			var vulnJSONPath []string
			for _, value := range vulnJSON.K("from").Array().Elements() {
				vulnJSONPath = append(vulnJSONPath, value.Stringify())
			}
			currentlyUpdatedVuln, _ := jsn.NewJson(vulnsForJira[vulnJSON.K("id").String().Value])
			vuln, _ = sjson.Set(currentlyUpdatedVuln.Stringify(), "from.-1", vulnJSONPath)
		}
		vulnsForJira[vulnJSON.K("id").String().Value] = vuln
	}
	return vulnsForJira
}
