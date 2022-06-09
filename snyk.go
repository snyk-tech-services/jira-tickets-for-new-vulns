package main

import (
	"errors"
	"log"

	"github.com/michael-go/go-jsn/jsn"
)

func getOrgProjects(Mf MandatoryFlags, customDebug debug) jsn.Json {
	responseData, err := makeSnykAPIRequest("GET", Mf.endpointAPI+"/v1/org/"+Mf.orgID+"/projects", Mf.apiToken, nil, customDebug)
	if err != nil {
		log.Printf("*** ERROR *** Could not get the Project(s) for endpoint %s\n", Mf.endpointAPI)
		log.Fatal(err)
	}

	project, err := jsn.NewJson(responseData)
	if err != nil {
		log.Fatal(err)
	}

	return project
}

func getProjectsIds(options flags, customDebug debug) ([]string, error) {

	var projectId []string
	if len(options.optionalFlags.projectID) == 0 {
		log.Println("*** INFO *** Project ID not specified - importing all projects")

		projects := getOrgProjects(options.mandatoryFlags, customDebug)

		for i := 0; i < len(projects.K("projects").Array().Elements()); i++ {
			p := projects.K("projects").Array().Elements()[i]
			projectId = append(projectId, string(p.K("id").String().Value))
		}

		if len(projectId) == 0 {
			return projectId, errors.New("Failure, Could not retrieve project ID")
		}
		return projectId, nil
	}

	projectId = append(projectId, options.optionalFlags.projectID)

	return projectId, nil
}

func getProjectDetails(Mf MandatoryFlags, projectID string, customDebug debug) jsn.Json {
	responseData, err := makeSnykAPIRequest("GET", Mf.endpointAPI+"/v1/org/"+Mf.orgID+"/project/"+projectID, Mf.apiToken, nil, customDebug)
	if err != nil {
		log.Printf("*** ERROR *** Could not get the Project(s) for endpoint %s\n", Mf.endpointAPI)
		log.Fatal(err)
	}

	project, err := jsn.NewJson(responseData)
	if err != nil {
		log.Fatal(err)
	}

	return project
}
