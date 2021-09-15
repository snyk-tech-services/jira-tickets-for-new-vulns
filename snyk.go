package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/michael-go/go-jsn/jsn"
)

func getOrgProjects(endpointAPI string, orgID string, token string) jsn.Json {
	responseData, err := makeSnykAPIRequest("GET", endpointAPI+"/v1/org/"+orgID+"/projects", token, nil)
	if err != nil {
		fmt.Printf("Could not get the Project(s) for endpoint %s\n", endpointAPI)
		log.Fatal(err)
	}

	project, err := jsn.NewJson(responseData)
	if err != nil {
		log.Fatal(err)
	}

	return project

}

func getProjectsIds(projectID string, endpointAPI string, orgID string, apiToken string) ([]string, error) {

	var projectId []string
	if len(projectID) == 0 {
		fmt.Println("Project ID not specified - importing all projects")

		projects := getOrgProjects(endpointAPI, orgID, apiToken)

		projectIdFound := make([]string, len(projects.K("projects").Array().Elements()))
		for i := 0; i < len(projects.K("projects").Array().Elements()); i++ {
			p := projects.K("projects").Array().Elements()[i]
			projectIdFound = append(projectId, string(p.K("id").String().Value))
		}

		if len(projectIdFound) == 0 {
			return projectIdFound, errors.New("Failure, Could not retrieve project ID")
		}
		return projectIdFound, nil
	}

	projectId = append(projectId, projectID)

	return projectId, nil
}

func getProjectDetails(endpointAPI string, orgID string, projectID string, token string) jsn.Json {
	responseData, err := makeSnykAPIRequest("GET", endpointAPI+"/v1/org/"+orgID+"/project/"+projectID, token, nil)
	if err != nil {
		fmt.Printf("Could not get the Project(s) for endpoint %s\n", endpointAPI)
		log.Fatal(err)
	}

	project, err := jsn.NewJson(responseData)
	if err != nil {
		log.Fatal(err)
	}

	return project

}
