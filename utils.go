package main

import (
	"encoding/json"
	"flag"
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
}

/***
Function setOption
set the optional flags structure
***/
func (Of *optionalFlags) setoptionalFlags(debugPtr bool, dryRunPtr bool, v viper.Viper) {

	Of.projectID = v.GetString("snyk.projectID")
	Of.jiraTicketType = v.GetString("jira.jiraTicketType")
	Of.severity = v.GetString("snyk.severity")
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
func (opt *flags) setOption() {

	var apiTokenPtr *string
	var debug bool
	var dryRun bool
	var configFilePtr *string
	v := viper.New()

	// flags are all setup at the same time so if one is all of them should be
	if pflag.Lookup("token") == nil {
		pflag.String("orgID", "", "Your Snyk Organization ID (check under Settings)")
		pflag.String("projectID", "", "Optional. Your Project ID. Will sync all projects Of your organization if not provided")
		pflag.String("api", "https://snyk.io/api", "Optional. Your API endpoint for onprem deployments (https://yourdeploymenthostname/api)")
		apiTokenPtr = pflag.String("token", "", "Your API token")
		pflag.String("jiraProjectID", "", "Your JIRA projectID (jiraProjectID or jiraProjectKey is required)")
		pflag.String("jiraProjectKey", "", "Your JIRA projectKey (jiraProjectID or jiraProjectKey is required)")
		pflag.String("jiraTicketType", "Bug", "Optional. Chosen JIRA ticket type")
		pflag.String("severity", "low", "Optional. Your severity threshold")
		pflag.String("maturityFilter", "", "Optional. include only maturity level(s) separated by commas [mature,proof-of-concept,no-known-exploit,no-data]")
		pflag.String("type", "all", "Optional. Your issue type (all|vuln|license)")
		pflag.String("assigneeName", "", "Optional. The Jira user ID to assign issues to. Note: Do not use assigneeName and assigneeId at the same time")
		pflag.String("assigneeId", "", "Optional. The Jira user ID to assign issues to. Note: Do not use assigneeName and assigneeId at the same time")
		pflag.String("labels", "", "Optional. Jira ticket labels")
		pflag.Bool("priorityIsSeverity", false, "Boolean. Use issue severity as priority")
		pflag.Int("priorityScoreThreshold", 0, "Optional. Your min priority score threshold [INT between 0 and 1000]")
		debugPtr := pflag.Bool("debug", false, "Optional. Boolean. enable debug mode")
		debug = *debugPtr
		dryRunPtr := pflag.Bool("dryRun", false, "Optional. Boolean. create a file with all the tickets without open them on jira")
		dryRun = *dryRunPtr
		pflag.Bool("ifUpgradeAvailableOnly", false, "Optional. Boolean. Open tickets only for upgradable issues")
		configFilePtr = pflag.String("configFile", "", "Optional. Config file path. Use config file to set parameters")
		pflag.Parse()

	} else {
		pflag.Parse()
		apiToken := pflag.Lookup("token").Value.String()
		apiTokenPtr = &apiToken
		debug = false
		dryRun = false
		configFileVal := pflag.Lookup("configFile").Value.String()
		configFilePtr = &configFileVal
		pflag.VisitAll(func(f *pflag.Flag) {
			pflag.Lookup(f.Name).Value.Set(f.Value.String())
		})
	}

	v.BindPFlag("snyk.orgID", pflag.Lookup("orgID"))
	v.BindPFlag("snyk.api", pflag.Lookup("api"))
	v.BindPFlag("jira.jiraProjectID", pflag.Lookup("jiraProjectID"))
	v.BindPFlag("jira.jiraProjectKey", pflag.Lookup("jiraProjectKey"))

	v.BindPFlag("snyk.projectID", pflag.Lookup("projectID"))
	v.BindPFlag("jira.jiraTicketType", pflag.Lookup("jiraTicketType"))
	v.BindPFlag("snyk.severity", pflag.Lookup("severity"))
	v.BindPFlag("snyk.type", pflag.Lookup("type"))
	v.BindPFlag("snyk.maturityFilter", pflag.Lookup("maturityFilter"))
	v.BindPFlag("jira.assigneeID", pflag.Lookup("assigneeId"))
	v.BindPFlag("jira.assigneeName", pflag.Lookup("assigneeName"))
	v.BindPFlag("jira.labels", pflag.Lookup("labels"))
	v.BindPFlag("jira.priorityIsSeverity", pflag.Lookup("priorityIsSeverity"))
	v.BindPFlag("snyk.priorityScoreThreshold", pflag.Lookup("priorityScoreThreshold"))
	v.BindPFlag("snyk.ifUpgradeAvailableOnly", pflag.Lookup("ifUpgradeAvailableOnly"))

	v.SetConfigName("jira") // config file name without extension
	v.SetConfigType("yaml")
	v.AddConfigPath(".")

	if configFilePtr != nil {
		v.AddConfigPath(*configFilePtr)
	} else {
		v.AddConfigPath(".")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Println("error no file")
		} else {
			fmt.Println("error ")
		}
	}

	log.Println("snyk.orgID: ", v.ConfigFileUsed())
	log.Println("snyk.orgID: ", v.AllSettings())

	// if configFilePtr != nil {
	// 	config = parseConfigFile(*configFilePtr)
	// }

	//log.Println("config.Snyk.EndpointAPI: ", config.Snyk.EndpointAPI)
	// 	// parse and then get the new value of the already existing *flag to set pointer
	// 	flag.Parse()

	// 	flag.VisitAll(func(f *flag.Flag) {
	// 		tmp := flag.Lookup(f.Name).Value.(flag.Getter).Get().(string)
	// 		//flagPtrName := f.Name + "Ptr"
	// 		for i = 1:N
	// 			config(i). = tmp ;
	// 		end

	// 	})

	// 	apiTokenString := flag.Lookup("token").Value.(flag.Getter).Get().(string)
	// 	apiTokenPtr = &apiTokenString
	// 	configFileString := flag.Lookup("configFile").Value.(flag.Getter).Get().(string)
	// 	configFilePtr = &configFileString
	// 	orgIDString := flag.Lookup("orgID").Value.(flag.Getter).Get().(string)
	// 	orgIDPtr = &orgIDString
	// 	projectIDString := flag.Lookup("projectID").Value.(flag.Getter).Get().(string)
	// 	projectIDPtr = &projectIDString
	// 	endpointAPIString := flag.Lookup("api").Value.(flag.Getter).Get().(string)
	// 	endpointAPIPtr = &endpointAPIString
	// 	jiraProjectIDString := flag.Lookup("jiraProjectID").Value.(flag.Getter).Get().(string)
	// 	jiraProjectIDPtr = &jiraProjectIDString
	// 	jiraProjectKeyString := flag.Lookup("jiraProjectKey").Value.(flag.Getter).Get().(string)
	// 	jiraProjectKeyPtr = &jiraProjectKeyString
	// 	jiraTicketTypeString := flag.Lookup("jiraTicketType").Value.(flag.Getter).Get().(string)
	// 	jiraTicketTypePtr = &jiraTicketTypeString
	// 	severityString := flag.Lookup("severity").Value.(flag.Getter).Get().(string)
	// 	severityPtr = &severityString
	// 	maturityFilterString := flag.Lookup("maturityFilter").Value.(flag.Getter).Get().(string)
	// 	maturityFilterPtr = &maturityFilterString
	// 	typeString := flag.Lookup("type").Value.(flag.Getter).Get().(string)
	// 	typePtr = &typeString
	// 	assigneeNameString := flag.Lookup("assigneeName").Value.(flag.Getter).Get().(string)
	// 	assigneeNamePtr = &assigneeNameString
	// 	assigneeIDString := flag.Lookup("assigneeId").Value.(flag.Getter).Get().(string)
	// 	assigneeIDPtr = &assigneeIDString
	// 	labelsString := flag.Lookup("labels").Value.(flag.Getter).Get().(string)
	// 	labelsPtr = &labelsString
	// 	priorityIsSeverityBool := flag.Lookup("priorityIsSeverity").Value.(flag.Getter).Get().(bool)
	// 	priorityIsSeverityPtr = &priorityIsSeverityBool
	// 	priorityScoreInt := flag.Lookup("priorityScoreThreshold").Value.(flag.Getter).Get().(int)
	// 	priorityScorePtr = &priorityScoreInt
	// 	debugBool := flag.Lookup("debug").Value.(flag.Getter).Get().(bool)
	// 	debugPtr = &debugBool
	// 	dryRunBool := flag.Lookup("dryRun").Value.(flag.Getter).Get().(bool)
	// 	dryRunPtr = &dryRunBool
	// 	ifUpgradeAvailableOnlyBool := flag.Lookup("ifUpgradeAvailableOnly").Value.(flag.Getter).Get().(bool)
	// 	ifUpgradeAvailableOnlyPtr = &ifUpgradeAvailableOnlyBool
	// }

	opt.mandatoryFlags.setMandatoryFlags(apiTokenPtr, *v)
	opt.optionalFlags.setoptionalFlags(debug, dryRun, *v)

	viper.Reset()
	//resetFlag()
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
