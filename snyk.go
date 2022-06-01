package main

import (
	"encoding/json"
	"errors"
	"log"
	"strings"

	"github.com/michael-go/go-jsn/jsn"
)

// ProjectsFilter is the top level filter type of filtering Snyk project
type ProjectsFilter struct {
	Filters ProjectsFilterBody `json:"filters"`
}

type ProjectsFilterBody struct {
	Attributes ProjectsFiltersAttributes `json:"attributes"`
}

type ProjectsFiltersAttributes struct {
	Criticality []string `json:"criticality,omitempty"`
	Environment []string `json:"environment,omitempty"`
	Lifecycle   []string `json:"lifecycle,omitempty"`
}

func getOrgProjects(flags flags, customDebug debug) jsn.Json {
	// According to https://snyk.docs.apiary.io/#reference/projects/all-projects/list-all-projects this should be
	// a POST API call but historically we used GET here. The following code maintains backwards compatibility for
	// existing cases where people aren't filtering projects by attributes, as it appears the API does not return
	// the full project list with empty attribute filters in the request body.
	verb := "GET"
	body := ProjectsFilter{}

	if len(flags.optionalFlags.projectCriticality) > 0 {
		body.Filters.Attributes.Criticality = strings.Split(flags.optionalFlags.projectCriticality, ",")
		verb = "POST"
	}

	if len(flags.optionalFlags.projectEnvironment) > 0 {
		body.Filters.Attributes.Environment = strings.Split(flags.optionalFlags.projectEnvironment, ",")
		verb = "POST"
	}

	if len(flags.optionalFlags.projectLifecycle) > 0 {
		body.Filters.Attributes.Lifecycle = strings.Split(flags.optionalFlags.projectLifecycle, ",")
		verb = "POST"
	}

	var marshalledBody []byte
	var err error

	if verb == "POST" {
		marshalledBody, err = json.Marshal(body)
		if err != nil {
			log.Fatalln(err)
		}
		log.Printf("Body: %s\n", string(marshalledBody))
	}

	responseData, err := makeSnykAPIRequest(verb, flags.mandatoryFlags.endpointAPI+"/v1/org/"+flags.mandatoryFlags.orgID+"/projects", flags.mandatoryFlags.apiToken, marshalledBody, customDebug)
	if err != nil {
		log.Printf("*** ERROR *** Could not get the Project(s) for endpoint %s\n", flags.mandatoryFlags.endpointAPI)
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
		log.Println("*** INFO *** Project ID not specified - importing all projects, subject to project attribute filters")

		projects := getOrgProjects(options, customDebug)

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
