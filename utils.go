package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

/*
**
Function setDebug and getDebug
**
*/
func (m *debug) setDebug(b bool) {
	m.PrintDebug = b
}

func (m *debug) getDebug() bool {
	return m.PrintDebug
}

/*
**
Function Debug
check if flag is set
print debug
**
*/
func (m *debug) Debug(args ...interface{}) {
	if m.PrintDebug {
		m.Print(args...)
	}
}

func (m *debug) Print(args ...interface{}) {
	log.Print(args...)
}

/*
**
Function Debugf
check if flag is set
print debug with formatting directive
**
*/
func (m *debug) Debugf(format string, args ...interface{}) {
	if m.PrintDebug {
		m.Printf(format, args...)
	}
}

func (m *debug) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

/*
**
Function setOption
set the mandatory flags structure
**
*/
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

/*
**
Function setOption
set the optional flags structure
**
*/
func (Of *optionalFlags) setOptionalFlags(debugPtr bool, dryRunPtr bool, v viper.Viper) {

	Of.projectID = v.GetString("snyk.projectID")
	Of.projectCriticality = v.GetString("snyk.projectCriticality")
	Of.projectEnvironment = v.GetString("snyk.projectEnvironment")
	Of.projectLifecycle = v.GetString("snyk.projectLifecycle")
	Of.jiraTicketType = v.GetString("jira.jiraTicketType")
	Of.severity = v.GetString("snyk.severity")
	Of.severityArray = v.GetString("snyk.severityArray")
	Of.issueType = v.GetString("snyk.type")
	Of.maturityFilterString = v.GetString("snyk.maturityFilter")
	Of.assigneeID = v.GetString("jira.assigneeID")
	Of.labels = v.GetString("jira.labels")
	Of.dueDate = v.GetString("jira.dueDate")
	Of.priorityIsSeverity = v.GetBool("jira.priorityIsSeverity")
	Of.priorityScoreThreshold = v.GetInt("snyk.priorityScoreThreshold")
	Of.debug = debugPtr
	Of.dryRun = dryRunPtr
	Of.cveInTitle = v.GetBool("jira.cveInTitle")
	Of.ifUpgradeAvailableOnly = v.GetBool("snyk.ifUpgradeAvailableOnly")
	Of.ifAutoFixableOnly = v.GetBool("snyk.ifAutoFixableOnly")
}

/*
**
Function resetFlag
reset commands line flags
**
*/
func resetFlag() {

	pflag.VisitAll(func(f *pflag.Flag) {
		pflag.Lookup(f.Name).Value.Set(f.DefValue)
	})

}

/*
**
Function setOption
get the arguments
set the flags structures
**
*/
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
	fs.String("api", "https://api.snyk.io", "Optional. Your API endpoint for onprem deployments (https://yourdeploymenthostname/api)")
	apiTokenPtr = fs.String("token", "", "Your API token")
	fs.String("jiraProjectID", "", "Your JIRA projectID (jiraProjectID or jiraProjectKey is required)")
	fs.String("jiraProjectKey", "", "Your JIRA projectKey (jiraProjectID or jiraProjectKey is required)")
	fs.String("jiraTicketType", "Bug", "Optional. Chosen JIRA ticket type")
	fs.String("severityArray", "", "Optional. Your severity array, to be used for multiple or specific severity")
	fs.String("projectCriticality", "", "Optional. Include only projects whose criticality attribute contains one or more of the specified values.")
	fs.String("projectEnvironment", "", "Optional. Include only projects whose environment attribute contains one or more of the specified values.")
	fs.String("projectLifecycle", "", "Optional. Include only projects whose lifecycle attribute contains one or more of the specified values.")
	fs.String("severity", "", "Optional. Your severity threshold")
	fs.String("maturityFilter", "", "Optional. include only maturity level(s) separated by commas [mature,proof-of-concept,no-known-exploit,no-data]")
	fs.String("type", "all", "Optional. Your issue type (all|vuln|license)")
	fs.String("assigneeId", "", "Optional. The Jira user accountId to assign issues to")
	fs.String("labels", "", "Optional. Jira ticket labels")
	fs.String("dueDate", "", "Optional. The built-in Due Date field")
	fs.Bool("priorityIsSeverity", false, "Boolean. Use issue severity as priority")
	fs.Int("priorityScoreThreshold", 0, "Optional. Your min priority score threshold [INT between 0 and 1000]")
	debugPtr = fs.Bool("debug", false, "Optional. Boolean. enable debug mode")
	dryRunPtr = fs.Bool("dryRun", false, "Optional. Boolean. Creates a file with all the tickets without open them on jira")
	fs.Bool("cveInTitle", false, "Optional. Boolean. Adds the CVEs to the jira ticket title")
	fs.Bool("ifUpgradeAvailableOnly", false, "Optional. Boolean. Opens tickets only for upgradable issues")
	fs.Bool("ifAutoFixableOnly", false, "Optional. Boolean. Opens tickets for issues that are fixable (no effect when using ifUpgradeAvailableOnly)")
	configFilePtr = fs.String("configFile", "", "Optional. Config file path. Use config file to set parameters")
	errParse := fs.Parse(args)
	if errParse != nil {
		log.Println("*** ERROR *** Error parsing command line arguments: ", errParse.Error())
		os.Exit(1)
	}

	// Have to set one by one because the name in the config file doesn't correspond to the flag name
	// This can be done at any time
	v.BindPFlag("snyk.orgID", fs.Lookup("orgID"))
	v.BindPFlag("snyk.api", fs.Lookup("api"))
	v.BindPFlag("jira.jiraProjectID", fs.Lookup("jiraProjectID"))
	v.BindPFlag("jira.jiraProjectKey", fs.Lookup("jiraProjectKey"))

	v.BindPFlag("snyk.projectID", fs.Lookup("projectID"))
	v.BindPFlag("snyk.projectCriticality", fs.Lookup("projectCriticality"))
	v.BindPFlag("snyk.projectEnvironment", fs.Lookup("projectEnvironment"))
	v.BindPFlag("snyk.projectLifecycle", fs.Lookup("projectLifecycle"))
	v.BindPFlag("jira.jiraTicketType", fs.Lookup("jiraTicketType"))
	v.BindPFlag("snyk.severity", fs.Lookup("severity"))
	v.BindPFlag("snyk.severityArray", fs.Lookup("severityArray"))
	v.BindPFlag("snyk.type", fs.Lookup("type"))
	v.BindPFlag("snyk.maturityFilter", fs.Lookup("maturityFilter"))
	v.BindPFlag("jira.assigneeID", fs.Lookup("assigneeId"))
	v.BindPFlag("jira.labels", fs.Lookup("labels"))
	v.BindPFlag("jira.cveInTitle", fs.Lookup("cveInTitle"))
	v.BindPFlag("jira.dueDate", fs.Lookup("dueDate"))
	v.BindPFlag("jira.priorityIsSeverity", fs.Lookup("priorityIsSeverity"))
	v.BindPFlag("snyk.priorityScoreThreshold", fs.Lookup("priorityScoreThreshold"))
	v.BindPFlag("snyk.ifUpgradeAvailableOnly", fs.Lookup("ifUpgradeAvailableOnly"))
	v.BindPFlag("snyk.ifAutoFixableOnly", fs.Lookup("ifAutoFixableOnly"))

	// Set and parse config file
	v.SetConfigName("jira") // config file name without extension
	v.SetConfigType("yaml")

	if configFilePtr != nil || len(*configFilePtr) > 0 {
		v.AddConfigPath(*configFilePtr)
	} else {
		v.AddConfigPath(".")
	}

	configFile, configFileLocation := ReadFile(*configFilePtr, true)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Println("*** WARN *** Config file is not found or maybe empty at location:", configFileLocation)
		} else {
			fmt.Println("*** ERROR *** ", err)
		}
	}

	customMandatoryJiraFields := CheckConfigFileFormat(configFile)
	opt.customMandatoryJiraFields = customMandatoryJiraFields

	// Setting the flags structure
	opt.mandatoryFlags.setMandatoryFlags(apiTokenPtr, *v)
	opt.optionalFlags.setOptionalFlags(*debugPtr, *dryRunPtr, *v)

	// check the flags rules
	opt.checkFlags()
}

/*
**
Function checkMandatoryAreSet
exit if the mandatory flags are missing
**
*/
func (flags *MandatoryFlags) checkMandatoryAreSet() {
	if len(flags.orgID) == 0 || len(flags.apiToken) == 0 || (len(flags.jiraProjectID) == 0 && len(flags.jiraProjectKey) == 0) {
		log.Println("*** ERROR *** Missing required flag(s). Please ensure orgID, token, jiraProjectID or jiraProjectKey are set.")
		os.Exit(1)
	}
}

/*
**
Function checkFlags
check flags rules
To work properly with jira these needs to be respected:
  - set only jiraProjectID or jiraProjectKey, not both
  - priorityScoreThreshold must be between 0 and 1000

**
*/
func (flags *flags) checkFlags() {
	if flags.mandatoryFlags.jiraProjectID != "" && flags.mandatoryFlags.jiraProjectKey != "" {
		log.Fatalf("*** ERROR *** You passed both jiraProjectID and jiraProjectKey in parameters\n Please, Use jiraProjectID OR jiraProjectKey, not both")
	}

	if flags.optionalFlags.priorityScoreThreshold < 0 || flags.optionalFlags.priorityScoreThreshold > 1000 {
		log.Fatalf("*** ERROR *** %d is not a valid score. Must be between 0-1000.", flags.optionalFlags.priorityScoreThreshold)
	}

	if flags.optionalFlags.severityArray != "" && flags.optionalFlags.severity != "" {
		log.Fatalf(("*** ERROR *** You passed both severityArray and severity in parameters\n Please, Use severityArray OR severity, not both"))
	}
}

/*
**
function CreateLogFile
return filename: string
argument: debug
Check if the file exist if not create it
**
*/

func CreateLogFile(customDebug debug, fileType string) string {

	// Get date
	date := getDate()

	// Set filename
	filename := fileType + date + ".json"

	// If the file doesn't exist, create it, or append to the file
	_, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Do not fail the tool if file cannot be created print a warning instead
		customDebug.Debug("*** ERROR *** Could not create log file")
		customDebug.Debug(err.Error())
	}

	return filename
}

/*
**
function getDate
return date: string
argument: none
return a string containing date and time
**
*/
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

/*
**
function getDate
return date: string
argument: none
return a string containing date and time
**
*/
func getDateDayOnly() string {

	now := time.Now().Round(0)
	y := fmt.Sprint(now.Year()) + "_"
	m := fmt.Sprint(int(now.Month())) + "_"
	d := fmt.Sprint(now.Day()) + "_"

	return y + m + d
}

/*
**
function writeLogFile
return date: string
input: map[string]interface{} logFile: details of the ticket to be written in the file
input: string filename: name of the file created in the main function
input: customDebug debug
Write the logFile in the file. Details are append to the file per project ID
**
*/
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

func Sprintf2(format string, a ...interface{}) string {
	a = append(a, "\r")
	return fmt.Sprintf(format, a...)
}

func writeErrorFile(function string, errorText string, customDebug debug) {

	errorsInterface := make(map[string]interface{})

	// Get filePath
	filename, err := FindFile("ErrorsFile")

	// Read the file, unMarshallto get a map[]interface{} and append the new error and Marshall to create a json
	// ReadFile
	jsonErrofile, _ := ReadFile(filename, false)

	// unMarshall
	err = json.Unmarshal(jsonErrofile, &errorsInterface)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file", err)
	}

	// Add the new error
	if errorsInterface[function] != nil {
		errorsInterface[function] = Sprintf2(errorText, errorsInterface[function])
	} else {
		errorsInterface[function] = errorText
	}

	NewErrorsList, err := json.Marshal(errorsInterface)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file, could not extract 'jira' config", err)
	}

	err = ioutil.WriteFile(filename, NewErrorsList, 0644)
	if err != nil {
		log.Fatal(err)
	}

	return
}

/*
**
function IsTestRun
return: none
input: boolean
check is the EXECUTION_ENVIRONMENT env is set
**
*/
func IsTestRun() bool {
	return os.Getenv("EXECUTION_ENVIRONMENT") == "test"
}

/*
**
function findCustomJiraMandatoryFlags
return: map[string]interface{} : list of mandatory fields and value associated
input: none
Read the config file and extract the jira fields than the mandatory field inside it
**
*/
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

/*
**
function convertYamltoJson
input map[interface{}]interface{}, type from unmarshalling yaml
return map[string]interface{} ticket type from unmarshalling json
convert the type we get from yaml to a json one
**
*/
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

/*
**
function CheckConfigFileFormat
input path string, path to the config file
return []byte config file
Try to read the yaml file. If this fails the config file is not valid yaml
**
*/
func CheckConfigFileFormat(yamlFile []byte) map[string]interface{} {

	// Check that each field in the file are supported by the tool
	config := make(map[interface{}]interface{})

	err := yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file", err)
	}

	// extract and check snyk fields
	snykValues := config["snyk"]
	if !checkSnykValue(snykValues) {
		log.Fatal()
	}

	// extract and check jira fields
	jiraValues := config["jira"]
	success, customFields := checkJiraValue(jiraValues)
	if !success {
		log.Fatal()
	}

	return customFields
}

func checkSnykValue(snykValues interface{}) bool {

	isSnykConfigOk := true

	unMarshalledSnykValues := make(map[interface{}]interface{})

	marshalledSnykValues, err := yaml.Marshal(snykValues)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file, could not extract 'snyk' config", err)
	}

	err = yaml.Unmarshal(marshalledSnykValues, &unMarshalledSnykValues)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file, could not extract 'snyk' config", err)
	}

	unMarshalledSnykValuesJson := convertYamltoJson(unMarshalledSnykValues)

	for key, value := range unMarshalledSnykValuesJson {

		// first check the key is supported
		switch key {
		// check the type of the value is valid
		case "projectID":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false
			}
		case "api":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false
			}
		case "orgID":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false
			}
		case "projectCriticality":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false
			}
		case "projectLifecycle":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false
			}
		case "projectEnvironment":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false
			}
		case "severity":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false
			}
		case "type":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false
			}
		case "maturityFilter":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false
			}
		case "priorityScoreThreshold":
			valueType := reflect.TypeOf(value).String()
			if valueType != "int" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be an integer", key, reflect.TypeOf(value).String())
				return false
			}
		case "ifUpgradeAvailableOnly":
			valueType := reflect.TypeOf(value).String()
			if valueType != "bool" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a boolean", key, reflect.TypeOf(value).String())
				return false
			}
		case "ifAutoFixableOnly":
			valueType := reflect.TypeOf(value).String()
			if valueType != "bool" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a boolean", key, reflect.TypeOf(value).String())
				return false
			}
		default:
			log.Printf("*** ERROR *** Please check the format config file, the snyk key %s is not supported by this tool", key)
			return false
		}
	}

	return isSnykConfigOk
}

func checkJiraValue(JiraValues interface{}) (bool, map[string]interface{}) {

	isJiraConfigOk := true

	yamlCustomJiraMandatoryField := make(map[interface{}]interface{})
	unMarshalledJiraValues := make(map[interface{}]interface{})
	customMandatoryJiraFields := make(map[string]interface{})

	marshalledJiraValues, err := yaml.Marshal(JiraValues)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file, could not extract 'snyk' config", err)
	}

	err = yaml.Unmarshal(marshalledJiraValues, &unMarshalledJiraValues)
	if err != nil {
		log.Println("*** ERROR *** Please check the format config file, could not extract 'snyk' config", err)
	}

	unMarshalledJiraValuesJson := convertYamltoJson(unMarshalledJiraValues)

	for key, value := range unMarshalledJiraValuesJson {

		// first check the key is supported
		switch key {
		// check the type of the value is valid
		case "jiraProjectID":
			valueType := reflect.TypeOf(value).String()
			if valueType != "int" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be an integer", key, reflect.TypeOf(value).String())
				return false, nil
			}
		case "jiraProjectKey":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false, nil
			}
		case "jiraTicketType":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false, nil
			}
		case "assigneeId":
			valueType := reflect.TypeOf(value).String()
			if valueType != "int" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be an integer", key, reflect.TypeOf(value).String())
				return false, nil
			}
		case "labels":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false, nil
			}
		case "dueDate":
			valueType := reflect.TypeOf(value).String()
			if valueType != "string" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a string", key, reflect.TypeOf(value).String())
				return false, nil
			}
		case "priorityIsSeverity":
			valueType := reflect.TypeOf(value).String()
			if valueType != "bool" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a boolean", key, reflect.TypeOf(value).String())
				return false, nil
			}
		case "cveInTitle":
			valueType := reflect.TypeOf(value).String()
			if valueType != "bool" {
				log.Printf("*** ERROR *** Please check the format config file, %s is of type %s when it should be a boolean", key, reflect.TypeOf(value).String())
				return false, nil
			}
		case "customMandatoryFields":
			customJiraMandatoryField_ := unMarshalledJiraValues["customMandatoryFields"]
			isJiraConfigOk_, customMandatoryJiraFields_ := checkMandatoryField(customJiraMandatoryField_, yamlCustomJiraMandatoryField)
			isJiraConfigOk = isJiraConfigOk_
			customMandatoryJiraFields = customMandatoryJiraFields_

		default:
			log.Printf("*** ERROR *** Please check the format config file, the jira key %s is not supported by this tool", key)
			return false, nil
		}
	}

	return isJiraConfigOk, customMandatoryJiraFields
}

// func checkMandatoryField(customJiraMandatoryField_ interface{}, yamlCustomJiraMandatoryField map[interface{}]interface{}) (bool, map[string]interface{}) {

// 	jsonCustomJiraMandatoryField := make(map[string]interface{})
// 	fields := make(map[string]interface{})

// 	marshalCustomJiraMandatoryField, err := yaml.Marshal(customJiraMandatoryField_)
// 	if err != nil {
// 		log.Println("*** ERROR *** Please check the format config file, could not extract 'customMandatoryFields' config", err)
// 	}

// 	err = yaml.Unmarshal(marshalCustomJiraMandatoryField, &yamlCustomJiraMandatoryField)
// 	if err != nil {
// 		log.Println("*** ERROR *** Please check the format config file, could not extract 'customMandatoryFields' config", err)
// 	}

// 	// converting the type, the yaml type is not compatible with the json one
// 	// json doesn't understand map[interface{}]interface{} => it will fail
// 	// when marshalling the ticket in a json format
// 	jsonCustomJiraMandatoryField = convertYamltoJson(yamlCustomJiraMandatoryField)

// 	log.Println("jsonCustomJiraMandatoryField, %s", jsonCustomJiraMandatoryField)

// 	for i, s := range jsonCustomJiraMandatoryField {

// 		value, ok := s.(map[string]interface{})
// 		if ok {
// 			v, ok := value["value"].(string)
// 			if ok {
// 				if strings.HasPrefix(v, JiraPrefix) {
// 					s, err = supportJiraFormats(v, debug{PrintDebug: false})
// 					if err != nil {
// 						log.Printf("*** ERROR *** Error while extracting the mandatory Jira fields configuration\n %s", err)
// 						return false, nil
// 					}
// 				}
// 			}
// 		} else {
// 			log.Println(fmt.Sprintf("*** ERROR *** Expected mandatory Jira fields configuration to be in format map[string]interface{}, received type: %T for field %s ", s, i))
// 			return false, nil
// 		}
// 		fields[i] = s
// 	}
// 	return true, fields
// }

func checkMandatoryField(customJiraMandatoryField_ interface{}, yamlCustomJiraMandatoryField map[interface{}]interface{}) (bool, map[string]interface{}) {

	jsonCustomJiraMandatoryField := make(map[string]interface{})
	fields := make(map[string]interface{})

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

	log.Println("jsonCustomJiraMandatoryField, %s", jsonCustomJiraMandatoryField)

	for i, s := range jsonCustomJiraMandatoryField {
		switch v := s.(type) {
		case string:
			fields[i] = v
		case map[string]interface{}:
			value, ok := v["value"].(string)
			if ok {
				if strings.HasPrefix(value, JiraPrefix) {
					s, err = supportJiraFormats(value, debug{PrintDebug: false})
					if err != nil {
						log.Printf("*** ERROR *** Error while extracting the mandatory Jira fields configuration\n %s", err)
						return false, nil
					}
				}
			}
			fields[i] = s
		default:
			log.Println(fmt.Sprintf("*** ERROR *** Unexpected type for field %s: %T", i, s))
			return false, nil
		}
	}
	return true, fields
}

/*
**
function ReadFile
input path string, path to the config file
return []byte config file
Try to read the yaml file. If this fails the config file is not valid yaml
**
*/
func ReadFile(path string, config bool) ([]byte, string) {

	if len(path) == 0 {
		path = "."
	}

	var err error
	filePath := path + "/jira.yaml"
	if !config {
		filePath, err = FindFile("ErrorsFile")
	}

	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Printf("*** ERROR *** Could not read file at location: %s. Please ensure the file exists and is formatted correctly.\nERROR: %s\n", filePath, err.Error())
	}

	return file, filePath
}

func FindFile(fileName string) (string, error) {

	// list all file in the directory
	fileInfo, err := ioutil.ReadDir(".")
	if err != nil {
		log.Fatal()
	}

	// Look for the one starting with listOfTicketCreated or ErrorsFile
	for _, file := range fileInfo {
		if !file.IsDir() {
			if strings.HasPrefix(file.Name(), fileName) {
				filePath := "./" + file.Name()
				return filePath, nil
			}
		}
	}
	errorMessage := fmt.Sprintf("Failure, Could not find File %s", fileName)
	return "", errors.New(errorMessage)
}