package main

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/michael-go/go-jsn/jsn"
)

// ProjectsFilter is the top level filter type of filtering Snyk project
type ProjectsFilter struct {
	Filters ProjectsFilterBody `json:"filters"`
}

type ProjectsFilterBody struct {
	Attributes *ProjectsFiltersAttributes `json:"attributes,omitempty"`
	Monitored  bool                       `json:"isMonitored"`
}

type ProjectsFiltersAttributes struct {
	Criticality []string `json:"criticality,omitempty"`
	Environment []string `json:"environment,omitempty"`
	Lifecycle   []string `json:"lifecycle,omitempty"`
}

func getOrgProjects(flags flags, customDebug debug) ([]jsn.Json, error) {
	// According to https://snyk.docs.apiary.io/#reference/projects/all-projects/list-all-projects this should be
	// a POST API call but historically we used GET here. The following code maintains backwards compatibility for
	// existing cases where people aren't filtering projects by attributes, as it appears the API does not return
	// the full project list with empty attribute filters in the request body.
	verb := "GET"
	api_version := "2022-07-08~beta"

	baseURL := flags.mandatoryFlags.endpointAPI + "/rest"

	projectsAPI := "/orgs/" + flags.mandatoryFlags.orgID + "/projects?version=" + api_version + "&status=active"
	if len(flags.optionalFlags.projectCriticality) > 0 || len(flags.optionalFlags.projectEnvironment) > 0 || len(flags.optionalFlags.projectLifecycle) > 0 {

		// TODO update examples to accurately reflect lowercase comma separated not square brackets
		if len(flags.optionalFlags.projectCriticality) > 0 {
			projectsAPI += "&businessCriticality=" + strings.Replace(flags.optionalFlags.projectCriticality, ",", "%2C", -1)
		}

		if len(flags.optionalFlags.projectEnvironment) > 0 {
			projectsAPI += "&environment=" + strings.Replace(flags.optionalFlags.projectEnvironment, ",", "%2C", -1)
		}

		if len(flags.optionalFlags.projectLifecycle) > 0 {
			projectsAPI += "&lifecycle=" + strings.Replace(flags.optionalFlags.projectLifecycle, ",", "%2C", -1)
		}
	}

	var err error

	if verb == "POST" {
		if err != nil {
			// FIXME: don't fall back, we should error instead
			log.Printf("*** ERROR *** Not able to read attributes %s\n", projectsAPI)
			errorMessage := fmt.Sprintf("Failure, Not able to read attributes\n")
			writeErrorFile("getOrgProjects", errorMessage, customDebug)
			err = errors.New(errorMessage)
			verb = "GET"
		}
	}

	projectList, err := makeSnykAPIRequest_REST(verb, baseURL, projectsAPI, flags.mandatoryFlags.apiToken, nil, customDebug)
	if err != nil {
		filters := "projectCriticality: " + flags.optionalFlags.projectCriticality + "\n projectEnvironment: " + flags.optionalFlags.projectEnvironment + "\n projectLifecycle: " + flags.optionalFlags.projectLifecycle
		log.Printf("*** ERROR *** Could not list the Project(s) for endpoint %s\n Applied Filters: %s\n", projectsAPI, filters)
		errorMessage := fmt.Sprintf("Failure, Could not list the Project(s) for endpoint %s .\n Applied filters: %s\n", projectsAPI, filters)
		writeErrorFile("getOrgProjects", errorMessage, customDebug)
		err = errors.New(errorMessage)
	}

	return projectList, err
}

func getProjectsIds(options flags, customDebug debug, notCreatedLogFile string) ([]string, error) {

	var projectIds []string
	if len(options.optionalFlags.projectID) == 0 {
		filters := "projectCriticality: " + options.optionalFlags.projectCriticality + "\n projectEnvironment: " + options.optionalFlags.projectEnvironment + "\n projectLifecycle: " + options.optionalFlags.projectLifecycle
		log.Println("*** INFO *** Project ID not specified - listing all projects that match the following filters: ", filters)

		projects, err := getOrgProjects(options, customDebug)
		if err != nil {
			message := fmt.Sprintf("error while getting projects ID for org %s", options.mandatoryFlags.orgID)
			writeErrorFile("getProjectsIds", message, customDebug)
			return nil, err
		}
	
		for _, project := range projects {
			projectID := project.K("id").String().Value
			projectIds = append(projectIds, projectID)
		}

		if len(projectIds) == 0 {
			ErrorMessage := fmt.Sprintf("Failure, Could not retrieve project ID")
			writeErrorFile("getProjectsIds", ErrorMessage, customDebug)
			return projectIds, errors.New(ErrorMessage)
		}
		return projectIds, nil
	}

	projectIds = append(projectIds, options.optionalFlags.projectID)

	return projectIds, nil
}

func getProjectDetails(Mf MandatoryFlags, projectID string, customDebug debug) (jsn.Json, error) {
	responseData, err := makeSnykAPIRequest("GET", Mf.endpointAPI+"/v1/org/"+Mf.orgID+"/project/"+projectID, Mf.apiToken, nil, customDebug)
	if err != nil {
		log.Printf("*** ERROR *** Could not get the Project detail for endpoint %s\n", Mf.endpointAPI)
		errorMessage := fmt.Sprintf("Failure, Could not get the Project detail for endpoint %s\n", Mf.endpointAPI)
		err = errors.New(errorMessage)
		writeErrorFile("getProjectDetails", errorMessage, customDebug)
	}

	project, err := jsn.NewJson(responseData)
	if err != nil {
		errorMessage := fmt.Sprintf("Failure, Could not read the Project detail for endpoint %s\n", Mf.endpointAPI)
		err = errors.New(errorMessage)
		writeErrorFile("getProjectDetails", errorMessage, customDebug)
	}

	return project, err
}
