package main

import (
	"log"

	"github.com/michael-go/go-jsn/jsn"
)

func getOrgProjects(endpointAPI string, orgID string, token string) jsn.Json {
	responseData := makeSnykAPIRequest("GET", endpointAPI+"/v1/org/"+orgID+"/projects", token, nil)

	project, err := jsn.NewJson(responseData)
	if err != nil {
		log.Fatal(err)
	}

	return project

}

func getProjectDetails(endpointAPI string, orgID string, projectID string, token string) jsn.Json {
	responseData := makeSnykAPIRequest("GET", endpointAPI+"/v1/org/"+orgID+"/project/"+projectID, token, nil)

	project, err := jsn.NewJson(responseData)
	if err != nil {
		log.Fatal(err)
	}

	return project

}
