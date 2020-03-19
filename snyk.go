package main

import (
	"log"

	"github.com/michael-go/go-jsn/jsn"
)

func getProjectDetails(endpointAPI string, orgID string, projectID string, token string) jsn.Json {
	responseData := makeSnykAPIRequest("GET", endpointAPI+"/v1/org/"+orgID+"/project/"+projectID, token, nil)

	project, err := jsn.NewJson(responseData)
	if err != nil {
		log.Fatal(err)
	}

	return project

}
