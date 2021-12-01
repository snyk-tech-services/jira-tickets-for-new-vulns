package main

import (
	"fmt"
	"log"
	"strings"
)

func main() {

	asciiArt :=
		`
================================================
  _____             _      _______        _     
 / ____|           | |    |__   __|      | |    
| (___  _ __  _   _| | __    | | ___  ___| |__  
 \___ \| '_ \| | | | |/ /    | |/ _ \/ __| '_ \ 
 ____) | | | | |_| |   <     | |  __/ (__| | | |
|_____/|_| |_|\__, |_|\_\    |_|\___|\___|_| |_|
              __/ /                            
             |___/                             
================================================
JIRA Syncing Tool
Open Source, so feel free to contribute !
================================================
`

	fmt.Println(asciiArt)

	// set Flags
	options := flags{}
	options.setOption()

	// enable debug
	customDebug := debug{}
	customDebug.setDebug(options.optionalFlags.debug)

	// test if mandatory flags are present
	options.mandatoryFlags.checkMandatoryAreSet()

	// Get the project ids associated with org
	// If project Id is not specified => get all the projets
	projectIDs, er := getProjectsIds(options, customDebug)
	if er != nil {
		log.Fatal(er)
	}

	customDebug.Debug("*** INFO *** options.optionalFlags", options.optionalFlags)
	customDebug.Debug("*** INFO *** options.MandatoryFlags", options.mandatoryFlags)

	// check flags are set according to rules
	options.checkFlags()

	maturityFilter := createMaturityFilter(strings.Split(options.optionalFlags.maturityFilterString, ","))
	numberIssueCreated := 0
	notCreatedJiraIssues := ""
	jiraResponse := ""
	var projectsTickets map[string]interface{}
	logFile := make(map[string]map[string]interface{})

	// Create the log file for the current run
	filename := CreateLogFile(customDebug)

	for _, project := range projectIDs {

		log.Println("*** INFO *** 1/4 - Retrieving Project", project)
		projectInfo := getProjectDetails(options.mandatoryFlags, project, customDebug)

		log.Println("*** INFO *** 2/4 - Getting Existing JIRA tickets")
		tickets := getJiraTickets(options.mandatoryFlags, project, customDebug)

		customDebug.Debug("*** INFO *** List of already existing tickets: ", tickets)

		log.Println("*** INFO *** 3/4 - Getting vulns")
		vulnsPerPath := getVulnsWithoutTicket(options, project, maturityFilter, tickets, customDebug)

		customDebug.Debug("*** INFO *** List of vuln without tickets: ", vulnsPerPath)

		if len(vulnsPerPath) == 0 {
			log.Println("*** INFO *** 4/4 - No new JIRA ticket required")
		} else {
			log.Println("*** INFO *** 4/4 - Opening JIRA Tickets")
			numberIssueCreated, jiraResponse, notCreatedJiraIssues, projectsTickets = openJiraTickets(options, projectInfo, vulnsPerPath, customDebug)
			if jiraResponse == "" && !options.optionalFlags.dryRun {
				log.Println("*** ERROR *** Failure to create a ticket(s)")
			}
			if options.optionalFlags.dryRun {
				fmt.Printf("\n----------PROJECT ID %s----------\n Dry run mode: no issue created\n------------------------------------------------------------------------\n", project)
			} else {
				fmt.Printf("\n----------PROJECT ID %s---------- \n Number of tickets created: %d\n List of issueId for which the ticket could not be created: %s\n-------------------------------------------------------------------\n", project, numberIssueCreated, notCreatedJiraIssues)
			}

			// Adding new project tickets detail to logfile struct
			// need to merge the map{string}interface{}
			// the new project one with the one containing all the
			// projects (could not find a better way for now)
			if projectsTickets != nil {
				newLogFile := make(map[string]interface{})
				for k, v := range projectsTickets {
					if _, ok := projectsTickets[k]; ok {
						newLogFile[k] = v
					}
				}

				for k, v := range logFile["projects"] {
					if _, ok := logFile["projects"][k]; ok {
						newLogFile[k] = v
					}
				}
				logFile["projects"] = newLogFile
			}
		}
	}

	// writing into the file
	writeLogFile(logFile, filename, customDebug)

	if options.optionalFlags.dryRun {
		fmt.Println("\n*************************************************************************************************************")
		fmt.Printf("\n******** Dry run list of ticket can be found in log file %s ********", filename)
		fmt.Println("\n*************************************************************************************************************")
	}
}
