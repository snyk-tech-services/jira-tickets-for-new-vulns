package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

/***
Function setDebug and getDebug
***/
func (m *debug) setDebug(b bool) {
	m.PrintDebug = b
}

func (m *debug) getDebug() bool {
	return m.PrintDebug
}

/***
Function Debug
check if flag is set
print debug
***/
func (m *debug) Debug(args ...interface{}) {
	if m.PrintDebug {
		m.Print(args...)
	}
}

func (m *debug) Print(args ...interface{}) {
	log.Print(args...)
}

/***
Function Debugf
check if flag is set
print debug with formatting directive
***/
func (m *debug) Debugf(format string, args ...interface{}) {
	if m.PrintDebug {
		m.Printf(format, args...)
	}
}

func (m *debug) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

/***
Function setOption
set the mandatory flags structure
***/
func (Mf *MandatoryFlags) setMandatoryFlags(orgIDPtr *string, endpointAPIPtr *string, apiTokenPtr *string,
	jiraProjectIDPtr *string, jiraProjectKeyPtr *string, config *config) {

	if config != nil {
		Mf.orgID = IfThenElseString((*orgIDPtr != ""), orgIDPtr, &config.Snyk.OrgID, "")
		Mf.endpointAPI = IfThenElseString((*endpointAPIPtr != ""), endpointAPIPtr, &config.Snyk.EndpointAPI, "https://snyk.io/api")
		Mf.apiToken = *apiTokenPtr
		Mf.jiraProjectID = IfThenElseString((*jiraProjectIDPtr != ""), jiraProjectIDPtr, &config.Jira.JiraProjectID, "")
		Mf.jiraProjectKey = IfThenElseString((*jiraProjectKeyPtr != ""), jiraProjectKeyPtr, &config.Jira.JiraProjectKey, "")
	} else {
		emptyString := ""
		Mf.orgID = *orgIDPtr
		Mf.endpointAPI = IfThenElseString((*endpointAPIPtr != ""), endpointAPIPtr, &emptyString, "https://snyk.io/api")
		Mf.apiToken = *apiTokenPtr
		Mf.jiraProjectID = *jiraProjectIDPtr
		Mf.jiraProjectKey = *jiraProjectKeyPtr
	}
}

/***
Function setOption
set the optional flags structure
***/
func (Of *optionalFlags) setoptionalFlags(projectIDPtr *string, jiraTicketTypePtr *string, severityPtr *string,
	maturityFilterPtr *string, typePtr *string, assigneeNamePtr *string,
	assigneeIDPtr *string, labelsPtr *string, priorityIsSeverityPtr *bool,
	priorityScorePtr *int, debugPtr *bool, dryRunPtr *bool, ifUpgradeAvailableOnlyPtr *bool, config *config) {

	if config != nil {
		Of.projectID = IfThenElseString((*projectIDPtr != ""), projectIDPtr, &config.Snyk.ProjectID, "")
		Of.jiraTicketType = IfThenElseString((*jiraTicketTypePtr != ""), jiraTicketTypePtr, &config.Jira.JiraTicketType, "Bug")
		Of.severity = IfThenElseString((*severityPtr != ""), severityPtr, &config.Snyk.Severity, "low")
		Of.issueType = IfThenElseString((*typePtr != ""), typePtr, &config.Snyk.IssueType, "all")
		Of.maturityFilterString = IfThenElseString((*maturityFilterPtr != ""), maturityFilterPtr, &config.Snyk.MaturityFilter, "")
		Of.assigneeID = IfThenElseString((*assigneeIDPtr != ""), assigneeIDPtr, &config.Jira.AssigneeId, "")
		Of.assigneeName = IfThenElseString((*assigneeNamePtr != ""), assigneeNamePtr, &config.Jira.AssigneeName, "")
		Of.labels = IfThenElseString((*labelsPtr != ""), labelsPtr, &config.Jira.Labels, "")
		Of.priorityIsSeverity = IfThenElseBool((*priorityIsSeverityPtr != false), priorityIsSeverityPtr, &config.Jira.PriorityIsSeverity)
		Of.priorityScoreThreshold = IfThenElseInt((*priorityScorePtr != 0), priorityScorePtr, &config.Snyk.PriorityScoreThreshold)
		Of.debug = *debugPtr
		Of.dryRun = *dryRunPtr
		Of.ifUpgradeAvailableOnly = IfThenElseBool((*ifUpgradeAvailableOnlyPtr != false), ifUpgradeAvailableOnlyPtr, &config.Snyk.IfUpgradeAvailableOnly)
	} else {
		emptyString := ""
		Of.projectID = *projectIDPtr
		Of.jiraTicketType = IfThenElseString((*jiraTicketTypePtr != ""), jiraTicketTypePtr, &emptyString, "Bug")
		Of.severity = IfThenElseString((*severityPtr != ""), severityPtr, &emptyString, "low")
		Of.issueType = IfThenElseString((*typePtr != ""), typePtr, &emptyString, "all")
		Of.maturityFilterString = *maturityFilterPtr
		Of.assigneeID = *assigneeIDPtr
		Of.assigneeName = *assigneeNamePtr
		Of.labels = *labelsPtr
		Of.priorityIsSeverity = *priorityIsSeverityPtr
		Of.priorityScoreThreshold = *priorityScorePtr
		Of.debug = *debugPtr
		Of.dryRun = *dryRunPtr
		Of.ifUpgradeAvailableOnly = *ifUpgradeAvailableOnlyPtr
	}
}

/***
Function resetFlag
reset commands line flags
***/
func resetFlag() {

	flag.Lookup("token").Value.Set("")
	flag.Lookup("orgID").Value.Set("")
	flag.Lookup("configFile").Value.Set("")
	flag.Lookup("projectID").Value.Set("")
	flag.Lookup("api").Value.Set("")
	flag.Lookup("jiraProjectID").Value.Set("")
	flag.Lookup("jiraProjectKey").Value.Set("")
	flag.Lookup("jiraTicketType").Value.Set("")

	flag.Lookup("severity").Value.Set("")
	flag.Lookup("maturityFilter").Value.Set("")
	flag.Lookup("type").Value.Set("")
	flag.Lookup("assigneeName").Value.Set("")
	flag.Lookup("assigneeId").Value.Set("")

	flag.Lookup("labels").Value.Set("")
	flag.Lookup("priorityIsSeverity").Value.Set("")
	flag.Lookup("priorityScoreThreshold").Value.Set("")
	flag.Lookup("debug").Value.Set("")
	flag.Lookup("dryRun").Value.Set("")
	flag.Lookup("ifUpgradeAvailableOnly").Value.Set("")
	flag.Lookup("configFile").Value.Set("")

}

/***
Function setOption
get the arguments
set the flags structures
***/
func (opt *flags) setOption() {

	var orgIDPtr *string
	var projectIDPtr *string
	var endpointAPIPtr *string
	var apiTokenPtr *string
	var jiraProjectIDPtr *string
	var jiraProjectKeyPtr *string
	var jiraTicketTypePtr *string
	var severityPtr *string
	var maturityFilterPtr *string
	var typePtr *string
	var assigneeNamePtr *string
	var assigneeIDPtr *string
	var labelsPtr *string
	var priorityIsSeverityPtr *bool
	var priorityScorePtr *int
	var debugPtr *bool
	var dryRunPtr *bool
	var ifUpgradeAvailableOnlyPtr *bool
	var configFilePtr *string
	var config *config

	// flags are all setup at the same tme so if one is all of them should be
	if flag.Lookup("token") == nil {
		orgIDPtr = flag.String("orgID", "", "Your Snyk Organization ID (check under Settings)")
		projectIDPtr = flag.String("projectID", "", "Optional. Your Project ID. Will sync all projects Of your organization if not provided")
		endpointAPIPtr = flag.String("api", "", "Optional. Your API endpoint for onprem deployments (https://yourdeploymenthostname/api)")
		apiTokenPtr = flag.String("token", "", "Your API token")
		jiraProjectIDPtr = flag.String("jiraProjectID", "", "Your JIRA projectID (jiraProjectID or jiraProjectKey is required)")
		jiraProjectKeyPtr = flag.String("jiraProjectKey", "", "Your JIRA projectKey (jiraProjectID or jiraProjectKey is required)")
		jiraTicketTypePtr = flag.String("jiraTicketType", "", "Optional. Chosen JIRA ticket type")
		severityPtr = flag.String("severity", "", "Optional. Your severity threshold")
		maturityFilterPtr = flag.String("maturityFilter", "", "Optional. include only maturity level(s) separated by commas [mature,proof-of-concept,no-known-exploit,no-data]")
		typePtr = flag.String("type", "", "Optional. Your issue type (all|vuln|license)")
		assigneeNamePtr = flag.String("assigneeName", "", "Optional. The Jira user ID to assign issues to. Note: Do not use assigneeName and assigneeId at the same time")
		assigneeIDPtr = flag.String("assigneeId", "", "Optional. The Jira user ID to assign issues to. Note: Do not use assigneeName and assigneeId at the same time")
		labelsPtr = flag.String("labels", "", "Optional. Jira ticket labels")
		priorityIsSeverityPtr = flag.Bool("priorityIsSeverity", false, "Boolean. Use issue severity as priority")
		priorityScorePtr = flag.Int("priorityScoreThreshold", 0, "Optional. Your min priority score threshold [INT between 0 and 1000]")
		debugPtr = flag.Bool("debug", false, "Optional. Boolean. enable debug mode")
		dryRunPtr = flag.Bool("dryRun", false, "Optional. Boolean. create a file with all the tickets without open them on jira")
		ifUpgradeAvailableOnlyPtr = flag.Bool("ifUpgradeAvailableOnly", false, "Optional. Boolean. Open tickets only for upgradable issues")
		configFilePtr = flag.String("configFile", "", "Optional. Config file path. Use config file to set parameters")
		flag.Parse()
	} else {
		// parse and then get the new value of the already existing flag to set pointer
		flag.Parse()
		apiTokenString := flag.Lookup("token").Value.(flag.Getter).Get().(string)
		apiTokenPtr = &apiTokenString
		configFileString := flag.Lookup("configFile").Value.(flag.Getter).Get().(string)
		configFilePtr = &configFileString
		orgIDString := flag.Lookup("orgID").Value.(flag.Getter).Get().(string)
		orgIDPtr = &orgIDString
		projectIDString := flag.Lookup("projectID").Value.(flag.Getter).Get().(string)
		projectIDPtr = &projectIDString
		endpointAPIString := flag.Lookup("api").Value.(flag.Getter).Get().(string)
		endpointAPIPtr = &endpointAPIString
		jiraProjectIDString := flag.Lookup("jiraProjectID").Value.(flag.Getter).Get().(string)
		jiraProjectIDPtr = &jiraProjectIDString
		jiraProjectKeyString := flag.Lookup("jiraProjectKey").Value.(flag.Getter).Get().(string)
		jiraProjectKeyPtr = &jiraProjectKeyString
		jiraTicketTypeString := flag.Lookup("jiraTicketType").Value.(flag.Getter).Get().(string)
		jiraTicketTypePtr = &jiraTicketTypeString
		severityString := flag.Lookup("severity").Value.(flag.Getter).Get().(string)
		severityPtr = &severityString
		maturityFilterString := flag.Lookup("maturityFilter").Value.(flag.Getter).Get().(string)
		maturityFilterPtr = &maturityFilterString
		typeString := flag.Lookup("type").Value.(flag.Getter).Get().(string)
		typePtr = &typeString
		assigneeNameString := flag.Lookup("assigneeName").Value.(flag.Getter).Get().(string)
		assigneeNamePtr = &assigneeNameString
		assigneeIDString := flag.Lookup("assigneeId").Value.(flag.Getter).Get().(string)
		assigneeIDPtr = &assigneeIDString
		labelsString := flag.Lookup("labels").Value.(flag.Getter).Get().(string)
		labelsPtr = &labelsString
		priorityIsSeverityBool := flag.Lookup("priorityIsSeverity").Value.(flag.Getter).Get().(bool)
		priorityIsSeverityPtr = &priorityIsSeverityBool
		priorityScoreInt := flag.Lookup("priorityScoreThreshold").Value.(flag.Getter).Get().(int)
		priorityScorePtr = &priorityScoreInt
		debugBool := flag.Lookup("debug").Value.(flag.Getter).Get().(bool)
		debugPtr = &debugBool
		dryRunBool := flag.Lookup("dryRun").Value.(flag.Getter).Get().(bool)
		dryRunPtr = &dryRunBool
		ifUpgradeAvailableOnlyBool := flag.Lookup("ifUpgradeAvailableOnly").Value.(flag.Getter).Get().(bool)
		ifUpgradeAvailableOnlyPtr = &ifUpgradeAvailableOnlyBool
	}

	if configFilePtr != nil {
		config = parseConfigFile(*configFilePtr)
	}

	opt.mandatoryFlags.setMandatoryFlags(orgIDPtr, endpointAPIPtr, apiTokenPtr, jiraProjectIDPtr, jiraProjectKeyPtr, config)
	opt.optionalFlags.setoptionalFlags(projectIDPtr, jiraTicketTypePtr, severityPtr, maturityFilterPtr,
		typePtr, assigneeNamePtr, assigneeIDPtr, labelsPtr, priorityIsSeverityPtr, priorityScorePtr,
		debugPtr, dryRunPtr, ifUpgradeAvailableOnlyPtr, config)

	resetFlag()
}

/***
Function checkMandatoryAreSet
exit if the mandatory flags are missing
***/
func (Mf *MandatoryFlags) checkMandatoryAreSet() {
	if len(Mf.orgID) == 0 || len(Mf.apiToken) == 0 || (len(Mf.jiraProjectID) == 0 && len(Mf.jiraProjectKey) == 0) {
		log.Println("*** ERROR *** Missing mandatory flags")
		flag.PrintDefaults()
		os.Exit(1)
	}
}

/***
Function checkFlags
check flags rules
To work properly with jira these needs to be respected:
	- set only jiraProjectID or jiraProjectKey, not both
	- priorityScoreThreshold must be between 0 and 1000
 	- set only assigneeName or assigneeID, not both
***/
func (flags *flags) checkFlags() {
	if flags.mandatoryFlags.jiraProjectID != "" && flags.mandatoryFlags.jiraProjectKey != "" {
		log.Fatalf(("*** ERROR *** You passed both jiraProjectID and jiraProjectKey in parameters\n Please, Use jiraProjectID OR jiraProjectKey, not both"))
	}

	if flags.optionalFlags.priorityScoreThreshold < 0 || flags.optionalFlags.priorityScoreThreshold > 1000 {
		log.Fatalf("*** ERROR *** %d is not a valid score. Must be between 0-1000.", flags.optionalFlags.priorityScoreThreshold)
	}

	if flags.optionalFlags.assigneeName != "" && flags.optionalFlags.assigneeID != "" {
		log.Fatalf(("*** ERROR *** You passed both assigneeID and assigneeName in parameters\n Please, Use assigneeID OR assigneeName, not both"))
	}
}

/***
function CreateLogFile
return filename: string
argument: debug
Check if the file exist if not create it
***/
func CreateLogFile(customDebug debug) string {

	// Get date
	date := getDate()

	// Set filename
	filename := "listOfTicketCreated_" + date + ".json"

	// If the file doesn't exist, create it, or append to the file
	_, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Do not fail the tool if file cannot be created print a warning instead
		customDebug.Debug("*** ERROR *** Could not create log file")
		customDebug.Debug(err.Error())
	}

	return filename
}

/***
function getDate
return date: string
argument: none
return a string containing date and time
***/
func getDate() string {

	now := time.Now().Round(0)
	y := fmt.Sprint(now.Year()) + "_"
	m := fmt.Sprint(int(now.Month())) + "_"
	d := fmt.Sprint(now.Day()) + "_"
	h := fmt.Sprint(now.Hour()) + "_"
	min := fmt.Sprint(now.Minute()) + "_"
	s := fmt.Sprint(now.Second())

	return y + m + d + h + min + s
}

/***
function writeLogFile
return date: string
input: map[string]interface{} logFile: details of the ticket to be written in the file
input: string filename: name of the file created in the main function
input: customDebug debug
Write the logFile in the file. Details are append to the file per project ID
***/
func writeLogFile(logFile map[string]map[string]interface{}, filename string, customDebug debug) {

	// If the file doesn't exist => exit, append to the file otherwise
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not open file ", filename)
		return
	}

	file, _ := json.MarshalIndent(logFile, "", "")

	if _, err := f.Write(file); err != nil {
		customDebug.Debug("*** ERROR *** Could write in file")
		return
	}

	if err := f.Close(); err != nil {
		customDebug.Debug("*** ERROR ***  Could not close file")
		return
	}

	return
}

/***
function parseConfigFile
return: none
input: flags
Parse the config file to set the flags
***/
func parseConfigFile(configPath string) *config {

	var config config

	//parse config file to extract values
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Printf("*** ERROR *** Error while reading config file %s :\n%v ", configPath, err)
	}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Printf("*** ERROR *** Error while parsing config file \n %v ", err)
	}

	return &config
}

/***
Function IfThenElseString
input condition: boolean
input value to return if condition is true *string
input value to return if condition is false *string
return a bool
main purpose is to do a comparison of int in one line
check if the flag is present if not check if value in config file exist
return default otherwise
***/
func IfThenElseString(condition bool, a *string, b *string, defaultValue string) string {

	if condition {
		return *a
	} else {
		// checking the second condition exist
		if *b != "" {
			return *b
		} else {
			return defaultValue
		}
	}
}

/***
Function IfThenElseBool
input condition: boolean
input value to return if condition is true *bool
input value to return if condition is false *bool
return a bool
main purpose is to do a comparison of int in one line
check if the flag is present if not check if value in config file exist
return default otherwise
***/
func IfThenElseBool(condition bool, a *bool, b *bool) bool {
	if condition {
		return *a
	} else {
		// checking the second condition exist
		if b != nil {
			return *b
		} else {
			return false
		}
	}
}

/***
Function IfThenElseInt
input condition: boolean
input value to return if condition is true *int
input value to return if condition is false *int
return an int
main purpose is to do a comparison of int in one line
check if the flag is present if not check if value in config file exist
return default otherwise
***/
func IfThenElseInt(condition bool, a *int, b *int) int {
	if condition {
		return *a
	} else {
		// checking the second condition exist
		if b != nil {
			return *b
		} else {
			return 0
		}
	}
}
