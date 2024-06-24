package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	// set Flags
	options := flags{}
	options.setOption(os.Args[1:])

	// enable debug
	customDebug := debug{}
	customDebug.setDebug(options.optionalFlags.debug)

	// test if mandatory flags are present
	options.mandatoryFlags.checkMandatoryAreSet()

	// Create the log file for the current run
	filenameNotCreated := CreateLogFile(customDebug, "ErrorsFile_")

	// Get the project ids associated with org
	// If project ID is not specified => get all the projects
	projectIDs, er := getProjectsIds(options, customDebug, filenameNotCreated)
	if er != nil {
		log.Fatal(er)
	}

	customDebug.Debug("*** INFO *** options.optionalFlags: ", options.optionalFlags)

	maturityFilter := createMaturityFilter(strings.Split(options.optionalFlags.maturityFilterString, ","))
	numberIssueCreated := 0
	notCreatedJiraIssues := ""
	jiraResponse := ""
	var projectsTickets map[string]interface{}
	logFile := make(map[string]map[string]interface{})

	// Create the log file for the current run
	filename := CreateLogFile(customDebug, "listOfTicketCreated_")

	for _, project := range projectIDs {

		log.Println("*** INFO *** Step 1/4 - Retrieving project", project)
		projectInfo, err := getProjectDetails(options.mandatoryFlags, project, customDebug)
		if err != nil {
			customDebug.Debug("*** ERROR *** could not get project details. Skipping project ", project)
			continue
		}

		log.Println("*** INFO *** Step 2/4 - Retrieving a list of existing Jira tickets")
		tickets, err := getJiraTickets(options.mandatoryFlags, project, customDebug)
		if err != nil {
			customDebug.Debug("*** ERROR *** could not get already existing tickets details. Skipping project ", project)
			continue
		}

		customDebug.Debug("*** INFO *** List of already existing tickets: ", tickets)

		log.Println("*** INFO *** Step 3/4 - Getting vulns")
		vulnsPerPath, skippedIssues, err := getVulnsWithoutTicket(options, project, maturityFilter, tickets, customDebug)
		if err != nil {
			customDebug.Debug("*** ERROR *** could not get vulnerability details. Skipping project ", project)
			continue
		}

		customDebug.Debug("*** INFO *** # of vulns without tickets: ", len(vulnsPerPath))

		if len(skippedIssues) > 0 {
			customDebug.Debug("*** INFO *** List of skipped vulns: ", skippedIssues)
			customDebug.Debug("*** INFO *** These have been skipped because data couldn't be retrieved from Snyk")
		}

		if len(vulnsPerPath) == 0 {
			log.Println("*** INFO *** Step 4/4 - No new Jira ticket required")
		} else {
			log.Println("*** INFO *** Step 4/4 - Opening Jira tickets")
			numberIssueCreated, jiraResponse, notCreatedJiraIssues, projectsTickets = openJiraTickets(options, projectInfo, vulnsPerPath, customDebug)
			if jiraResponse == "" && !options.optionalFlags.dryRun {
				log.Println("*** ERROR *** Failed to create Jira ticket(s)")
			}
			if options.optionalFlags.dryRun {
				fmt.Printf("\n----------PROJECT ID %s----------\n Dry run mode: no issue created\n------------------------------------------------------------------------\n", project)
			} else {
				fmt.Printf("\n----------PROJECT ID %s---------- \n Number of tickets created: %d\n List of issueIds for which Jira ticket(s) could not be created: %s\n-------------------------------------------------------------------\n", project, numberIssueCreated, notCreatedJiraIssues)
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

	// TODO: add the list of not created tickets

	if options.optionalFlags.dryRun {
		fmt.Println("\n*************************************************************************************************************")
		fmt.Printf("\n******** Dry run list of ticket can be found in log file %s ********", filename)
		fmt.Println("\n*************************************************************************************************************")
	}
}