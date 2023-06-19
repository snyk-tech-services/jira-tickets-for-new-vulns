package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

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

type Link struct {
	NEXT string `json:"next"`
}

type ProjectWithId struct {
	ID string `json:"id"`
}

type ProjectsData struct {
	DATA  []ProjectWithId `json:"data"`
	LINKS Link `json:"links"`
}

func snykProjectsAPICall(flags flags, customDebug debug) ([]string, error) {
	// Doing this for test propose
	endpointAPI := "https://api.snyk.io"
	if IsTestRun() {
		endpointAPI = flags.mandatoryFlags.endpointAPI
	}

	// https://apidocs.snyk.io/?version=2022-07-08~beta#get-/orgs/-org_id-
	verb := "GET"
	endpoint := fmt.Sprintf("%s/rest/orgs/%s/projects&version=2022-07-08~beta&status=active", endpointAPI, flags.mandatoryFlags.orgID)

	if len(flags.optionalFlags.projectCriticality) > 0 {
		endpoint += fmt.Sprintf("&businessCriticality=%v", flags.optionalFlags.projectCriticality)
	}

	if len(flags.optionalFlags.projectEnvironment) > 0 {
		endpoint += fmt.Sprintf("&environment=%v", flags.optionalFlags.projectEnvironment)
	}

	if len(flags.optionalFlags.projectLifecycle) > 0 {
		endpoint += fmt.Sprintf("&lifecycle=%v", flags.optionalFlags.projectLifecycle)
	}

	var err error
	var projectIds []string

	for {
		// get the list of code issue for this project
		responseData, err := makeSnykAPIRequest(verb, endpoint, flags.mandatoryFlags.apiToken, nil, customDebug)
		if err != nil {
			filters := "projectCriticality: " + flags.optionalFlags.projectCriticality + "\n projectEnvironment: " + flags.optionalFlags.projectEnvironment + "\n projectLifecycle: " + flags.optionalFlags.projectLifecycle
			log.Printf("*** ERROR *** Could not list the Project(s) for endpoint %s\n Applied Filters: %s\n", endpoint, filters)
			errorMessage := fmt.Sprintf("Failure, Could not list the Project(s) for endpoint %s .\n Applied filters: %s\n", endpoint, filters)
			writeErrorFile("snykProjectsAPICall", errorMessage, customDebug)
			err = errors.New(errorMessage)
		}
		var projectsData ProjectsData

		err = json.Unmarshal(responseData, &projectsData)
		if err != nil {
			log.Printf("*** ERROR *** Could not get read the response from endpoint %s\n", endpoint)
			errorMessage := fmt.Sprintf("Failure, Could not get read the response from endpoint %s ", endpoint)
			writeErrorFile("snykProjectsAPICall", errorMessage, customDebug)
			err = errors.New(errorMessage)
		}

		for _, project := range projectsData.DATA {
			if err != nil {
				fmt.Println("Error:", err)
				return nil, err
			}
			projectIds = append(projectIds, project.ID)
		}

		if len(projectsData.LINKS.NEXT) > 0 {
			endpoint = endpointAPI + "/rest" + projectsData.LINKS.NEXT
		} else {
			break
		}
	}

	return projectIds, err
}

func getProjectsIds(options flags, customDebug debug, notCreatedLogFile string) ([]string, error) {

	var projectIds []string
	if len(options.optionalFlags.projectID) > 0 {

		filters := "projectCriticality: " + options.optionalFlags.projectCriticality + "\n projectEnvironment: " + options.optionalFlags.projectEnvironment + "\n projectLifecycle: " + options.optionalFlags.projectLifecycle
		log.Println("*** INFO *** Project ID not specified - listing all projects that match the following filters: ", filters)

		projectIds, err := snykProjectsAPICall(options, customDebug)
		if err != nil {
			message := fmt.Sprintf("error while getting projects ID for org %s", options.mandatoryFlags.orgID)
			writeErrorFile("getProjectsIds", message, customDebug)
			return nil, err
		}

		if len(projectIds) == 0 {
			ErrorMessage := fmt.Sprintf("Failure, Could not retrieve project ID")
			writeErrorFile("getProjectsIds", ErrorMessage, customDebug)
			return projectIds, errors.New(ErrorMessage)
		}
		return projectIds, nil
	}

	projectIds = append(projectIds, string(options.optionalFlags.projectID))

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
