package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/michael-go/go-jsn/jsn"
)

func getOrgProjects(endpointAPI string, orgID string, token string, repoName string) jsn.Json {
	responseData, err := makeSnykAPIRequest("GET", endpointAPI+"/v1/org/"+orgID+"/projects", token, nil)
	if err != nil {
		fmt.Printf("Could not get the Project(s) for endpoint %s\n", endpointAPI)
		log.Fatal(err)
	}

	project, err := jsn.NewJson(responseData)
	if err != nil {
		log.Fatal(err)
	}

	if repoName != "" {

		orgApiResponse := make(map[string]interface{})
		json.Unmarshal([]byte(responseData), &orgApiResponse)

		// keeping the content of org and project
		orgInfo := orgApiResponse["org"].(map[string]interface{})
		projectsInfo := orgApiResponse["projects"].([]interface{})

		newProject := make(map[string]interface{})
		newProject["org"] = orgInfo

		var newProjectInfo []interface{}
		for i := 0; i < len(projectsInfo); i++ {

			var branchName string
			var NameFromApiArray []string
			var newNameFromApi string

			// TODO this is a debug
			// fmt.Println("projectsInfo[i]: ", projectsInfo[i])
			projectInfo := projectsInfo[i].(map[string]interface{})
			NameFromApi := projectInfo["name"].(string)

			if projectInfo["branch"] != nil {
				branchName = "(" + projectInfo["branch"].(string) + ")"
			}

			newNameFromApi = NameFromApi

			// removing the file name if exist
			if strings.Contains(NameFromApi, ":") {
				NameFromApiArray = strings.Split(NameFromApi, ":")
				// TODO add this to debug option
				//fmt.Println("Info: repo name found in api response: ", NameFromApiArray[0])
				newNameFromApi = NameFromApiArray[0]
			}

			// removing the branch name if exist
			if strings.Contains(newNameFromApi, branchName) {
				// TODO add this to debug option
				//fmt.Println("Info: Removing the branch name from the repoName found in API response", newNameFromApi)
				newNameFromApi = strings.TrimSuffix(newNameFromApi, branchName)
			}

			if newNameFromApi == repoName {
				// TODO add this to debug option
				//fmt.Println("Found details for project in repo ", repoName)
				newProjectInfo = append(newProjectInfo, projectInfo)
			}
		}

		if newProjectInfo == nil {
			fmt.Printf("Couldn't find project(s) for corresponding to RepoName %s for endpoint %s", repoName, endpointAPI)
			log.Fatal()
		}
		newProject["projects"] = newProjectInfo

		marshalledNewProject, _ := json.Marshal(newProject)
		project, err = jsn.NewJson(marshalledNewProject)
	}

	// TODO add this to debug option
	// fmt.Println("project: ", project)

	return project
}

func getProjectsIds(projectID string, endpointAPI string, orgID string, apiToken string, repoName string) ([]string, error) {

	var projectId []string
	if len(projectID) == 0 {
		fmt.Println("Project ID not specified - importing all projects")

		projects := getOrgProjects(endpointAPI, orgID, apiToken, repoName)

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
