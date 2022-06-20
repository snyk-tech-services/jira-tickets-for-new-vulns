package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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
func (Mf *MandatoryFlags) setMandatoryFlags(apiTokenPtr *string, v viper.Viper) {

	Mf.orgID = v.GetString("snyk.orgID")
	Mf.endpointAPI = v.GetString("snyk.api")
	Mf.apiToken = *apiTokenPtr
	Mf.jiraProjectID = v.GetString("jira.jiraProjectID")
	Mf.jiraProjectKey = v.GetString("jira.jiraProjectKey")

	// Checking flag exist
	// pflag required function does not work with viper
	Mf.checkMandatoryAreSet()
}

/***
Function setOption
set the optional flags structure
***/
func (Of *optionalFlags) setoptionalFlags(debugPtr bool, dryRunPtr bool, v viper.Viper) {

	Of.projectID = v.GetString("snyk.projectID")
	Of.jiraTicketType = v.GetString("jira.jiraTicketType")
	Of.severityThreshold = v.GetString("snyk.severityThreshold")
	Of.severities = v.GetString("snyk.severities")
	Of.issueType = v.GetString("snyk.type")
	Of.maturityFilterString = v.GetString("snyk.maturityFilter")
	Of.assigneeID = v.GetString("jira.assigneeID")
	Of.assigneeName = v.GetString("jira.assigneeName")
	Of.labels = v.GetString("jira.labels")
	Of.priorityIsSeverity = v.GetBool("jira.priorityIsSeverity")
	Of.priorityScoreThreshold = v.GetInt("snyk.priorityScoreThreshold")
	Of.debug = debugPtr
	Of.dryRun = dryRunPtr
	Of.ifUpgradeAvailableOnly = v.GetBool("snyk.ifUpgradeAvailableOnly")

}

/***
Function resetFlag
reset commands line flags
***/
func resetFlag() {

	pflag.VisitAll(func(f *pflag.Flag) {
		pflag.Lookup(f.Name).Value.Set(f.DefValue)
	})

}

/***
Function setOption
get the arguments
set the flags structures
***/
func (opt *flags) setOption(args []string) {

	var apiTokenPtr *string
	var debugPtr *bool
	var dryRunPtr *bool
	var configFilePtr *string

	// Using viper to bind config file and flags
	v := viper.New()

	// flags are all setup at the same time so if one is all of them should be enough
	fs := pflag.NewFlagSet("", pflag.ContinueOnError)

	fs.String("orgID", "", "Your Snyk Organization ID (check under Settings)")
	fs.String("projectID", "", "Optional. Your Project ID. Will sync all projects Of your organization if not provided")
	fs.String("api", "https://snyk.io/api", "Optional. Your API endpoint for onprem deployments (https://yourdeploymenthostname/api)")
	apiTokenPtr = fs.String("token", "", "Your API token")
	fs.String("jiraProjectID", "", "Your JIRA projectID (jiraProjectID or jiraProjectKey is required)")
	fs.String("jiraProjectKey", "", "Your JIRA projectKey (jiraProjectID or jiraProjectKey is required)")
	fs.String("jiraTicketType", "Bug", "Optional. Chosen JIRA ticket type")
	fs.String("severities", "", "Optional. Your severity array, to be used for multiple or specific severity")
	fs.String("severityThreshold", "", "Optional. Your severity threshold, defaults to low")
	fs.String("maturityFilter", "", "Optional. include only maturity level(s) separated by commas [mature,proof-of-concept,no-known-exploit,no-data]")
	fs.String("type", "all", "Optional. Your issue type (all|vuln|license)")
	fs.String("assigneeName", "", "Optional. The Jira user ID to assign issues to. Note: Do not use assigneeName and assigneeId at the same time")
	fs.String("assigneeId", "", "Optional. The Jira user ID to assign issues to. Note: Do not use assigneeName and assigneeId at the same time")
	fs.String("labels", "", "Optional. Jira ticket labels")
	fs.Bool("priorityIsSeverity", false, "Boolean. Use issue severity as priority")
	fs.Int("priorityScoreThreshold", 0, "Optional. Your min priority score threshold [INT between 0 and 1000]")
	debugPtr = fs.Bool("debug", false, "Optional. Boolean. enable debug mode")
	dryRunPtr = fs.Bool("dryRun", false, "Optional. Boolean. create a file with all the tickets without open them on jira")
	fs.Bool("ifUpgradeAvailableOnly", false, "Optional. Boolean. Open tickets only for upgradable issues")
	configFilePtr = fs.String("configFile", "", "Optional. Config file path. Use config file to set parameters")
	fs.Parse(args)

	// Have to set one by one because the name in the config file doesn't correspond to the flag name
	// This can be done at any time
	v.BindPFlag("snyk.orgID", fs.Lookup("orgID"))
	v.BindPFlag("snyk.api", fs.Lookup("api"))
	v.BindPFlag("jira.jiraProjectID", fs.Lookup("jiraProjectID"))
	v.BindPFlag("jira.jiraProjectKey", fs.Lookup("jiraProjectKey"))

	v.BindPFlag("snyk.projectID", fs.Lookup("projectID"))
	v.BindPFlag("jira.jiraTicketType", fs.Lookup("jiraTicketType"))
	v.BindPFlag("snyk.severityThreshold", fs.Lookup("severityThreshold"))
	v.BindPFlag("snyk.severities", fs.Lookup("severities"))
	v.BindPFlag("snyk.type", fs.Lookup("type"))
	v.BindPFlag("snyk.maturityFilter", fs.Lookup("maturityFilter"))
	v.BindPFlag("jira.assigneeID", fs.Lookup("assigneeId"))
	v.BindPFlag("jira.assigneeName", fs.Lookup("assigneeName"))
	v.BindPFlag("jira.labels", fs.Lookup("labels"))
	v.BindPFlag("jira.priorityIsSeverity", fs.Lookup("priorityIsSeverity"))
	v.BindPFlag("snyk.priorityScoreThreshold", fs.Lookup("priorityScoreThreshold"))
	v.BindPFlag("snyk.ifUpgradeAvailableOnly", fs.Lookup("ifUpgradeAvailableOnly"))

	// Set and parse config file
	v.SetConfigName("jira") // config file name without extension
	v.SetConfigType("yaml")

	if configFilePtr != nil || len(*configFilePtr) > 0 {
		v.AddConfigPath(*configFilePtr)
	} else {
		v.AddConfigPath(".")
	}

	configFile, configFileLocation := CheckConfigFileFormat(*configFilePtr)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Println("*** WARN *** Config file is not found or maybe empty at location:", configFileLocation)
		} else {
			fmt.Println("*** ERROR *** ", err)
		}
	}

	// Get any mandatory custom jira configuration
	// needed to open a jira ticket
	// don't do something not needed
	if v.Get("jira.customMandatoryFields") != nil {
		opt.customMandatoryJiraFields = findCustomJiraMandatoryFlags(configFile)
	}

	// Setting the flags structure
	opt.mandatoryFlags.setMandatoryFlags(apiTokenPtr, *v)
	opt.optionalFlags.setoptionalFlags(*debugPtr, *dryRunPtr, *v)

	// check the flags rules
	opt.checkFlags()
}

/***
Function checkMandatoryAreSet
exit if the mandatory flags are missing
***/
func (flags *MandatoryFlags) checkMandatoryAreSet() {
	if len(flags.orgID) == 0 || len(flags.apiToken) == 0 || (len(flags.jiraProjectID) == 0 && len(flags.jiraProjectKey) == 0) {
		log.Println("*** ERROR *** Missing required flag(s). Please ensure orgID, token, jiraProjectID or jiraProjectKey are set.")
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

	if flags.optionalFlags.severities != "" && flags.optionalFlags.severityThreshold != "" {
		log.Fatalf(("*** ERROR *** You passed both severities and severityThreshold in parameters\n Please, Use severities OR severityThreshold, not both"))
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
function getDate
return date: string
argument: none
return a string containing date and time
***/
func getDateDayOnly() string {

	now := time.Now().Round(0)
	y := fmt.Sprint(now.Year()) + "_"
	m := fmt.Sprint(int(now.Month())) + "_"
	d := fmt.Sprint(now.Day()) + "_"

	return y + m + d
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

func writeErrorFile(errorText string, customDebug debug) {

	// Get date
	date := getDateDayOnly()

	// Set filename
	filename := "Error_" + date + ".json"

	// If the file doesn't exist => create it, append to the file otherwise
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		customDebug.Debug("*** ERROR *** Could not open file ", filename)
		return
	}

	errorTextByte := []byte(errorText + "\n")

	if _, err := f.Write(errorTextByte); err != nil {
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
function IsTestRun
return: none
input: boolean
check is the EXECUTION_ENVIRONMENT env is set
***/
func IsTestRun() bool {
	return os.Getenv("EXECUTION_ENVIRONMENT") == "test"
}

/***
function findCustomJiraMandatoryFlags
return: map[string]interface{} : list of mandatory fields and value associated
input: none
Read the config file and extract the jira fields than the mandatory field inside it
***/
func findCustomJiraMandatoryFlags(yamlFile []byte) map[string]interface{} {

	config := make(map[interface{}]interface{})
	yamlCustomJiraMandatoryField := make(map[interface{}]interface{})
	jsonCustomJiraMandatoryField := make(map[string]interface{})
	unMarshalledJiraValues := make(map[interface{}]interface{})

	err := yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file", err)
	}

	// extract jira fields
	jiraValues := config["jira"]
	marshalledJiraValues, err := yaml.Marshal(jiraValues)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file, could not extract 'jira' config", err)
	}

	err = yaml.Unmarshal(marshalledJiraValues, &unMarshalledJiraValues)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file, could not extract 'jira' config", err)
	}

	// extract mandatory fields
	customJiraMandatoryField_ := unMarshalledJiraValues["customMandatoryFields"]

	marshalCustomJiraMandatoryField, err := yaml.Marshal(customJiraMandatoryField_)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file, could not extract 'customMandatoryFields' config", err)
	}

	err = yaml.Unmarshal(marshalCustomJiraMandatoryField, &yamlCustomJiraMandatoryField)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file, could not extract 'customMandatoryFields' config", err)
	}

	// converting the type, the yaml type is not compatible with the json one
	// json doesn't understand map[interface{}]interface{} => it will fail
	// when marshalling the ticket in a json format
	jsonCustomJiraMandatoryField = convertYamltoJson(yamlCustomJiraMandatoryField)

	return jsonCustomJiraMandatoryField
}

/***
function convertYamltoJson
input map[interface{}]interface{}, type from unmarshalling yaml
return map[string]interface{} ticket type from unmarshalling json
convert the type we get from yaml to a json one
***/
func convertYamltoJson(m map[interface{}]interface{}) map[string]interface{} {
	res := map[string]interface{}{}
	for k, v := range m {
		switch v2 := v.(type) {
		case map[interface{}]interface{}:
			res[fmt.Sprint(k)] = convertYamltoJson(v2)
		default:
			res[fmt.Sprint(k)] = v
		}
	}
	return res
}

/***
function CheckConfigFileFormat
input path string, path to the config file
return []byte config file
Try to read the yaml file. If this fails the config file is not valid yaml
***/
func CheckConfigFileFormat(path string)([]byte, string) {

	if len(path) == 0 {
		path = "."
	}

	file := path + "/jira.yaml"

	yamlFile, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Printf("*** ERROR *** Could not read config file at location: %s. Please ensure the file exists and is formatted correctly.\nERROR: %s\n", file, err.Error())
	}

	return yamlFile, file
}
