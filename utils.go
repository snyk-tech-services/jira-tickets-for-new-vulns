package main

import (
	"flag"
	"log"
	"os"
)

// Debug

// structure containing the debug flag to check on
type debug struct {
	PrintDebug bool
}

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

// Flags
// flags structures
// separated in 2 structure because some function needs only the mandatory
type flags struct {
	mandatoryFlags MandatoryFlags
	optionalFlags  optionalFlags
}

type MandatoryFlags struct {
	orgID          string
	endpointAPI    string
	apiToken       string
	jiraProjectID  string
	jiraProjectKey string
}

type optionalFlags struct {
	projectID              string
	jiraTicketType         string
	severity               string
	issueType              string
	maturityFilterString   string
	assigneeID             string
	assigneeName           string
	labels                 string
	priorityIsSeverity     bool
	priorityScoreThreshold int
	debug                  bool
	dryRun                 bool
}

/***
Function setOption
set the mandatory flags structure
***/
func (Mf *MandatoryFlags) setMandatoryFlags(orgIDPtr *string, endpointAPIPtr *string, apiTokenPtr *string,
	jiraProjectIDPtr *string, jiraProjectKeyPtr *string) {

	Mf.orgID = *orgIDPtr
	Mf.endpointAPI = *endpointAPIPtr
	Mf.apiToken = *apiTokenPtr
	Mf.jiraProjectID = *jiraProjectIDPtr
	Mf.jiraProjectKey = *jiraProjectKeyPtr

}

/***
Function setOption
set the optional flags structure
***/
func (Of *optionalFlags) setoptionalFlags(projectIDPtr *string, jiraTicketTypePtr *string, severityPtr *string,
	maturityFilterPtr *string, typePtr *string, assigneeIDPtr *string,
	assigneeNamePtr *string, labelsPtr *string, priorityIsSeverityPtr *bool,
	priorityScorePtr *int, debugPtr *bool, dryRunPtr *bool) {

	Of.projectID = *projectIDPtr
	Of.jiraTicketType = *jiraTicketTypePtr
	Of.severity = *severityPtr
	Of.issueType = *typePtr
	Of.maturityFilterString = *maturityFilterPtr
	Of.assigneeID = *assigneeIDPtr
	Of.assigneeName = *assigneeNamePtr
	Of.labels = *labelsPtr
	Of.priorityIsSeverity = *priorityIsSeverityPtr
	Of.priorityScoreThreshold = *priorityScorePtr
	Of.debug = *debugPtr
	Of.dryRun = *dryRunPtr
}

/***
Function setOption
get the arguments
set the flags structures
***/
func (opt *flags) setOption() {

	orgIDPtr := flag.String("orgID", "", "Your Snyk Organization ID (check under Settings)")
	projectIDPtr := flag.String("projectID", "", "Optional. Your Project ID. Will sync all projects Of your organization if not provided")
	endpointAPIPtr := flag.String("api", "https://snyk.io/api", "Optional. Your API endpoint for onprem deployments (https://yourdeploymenthostname/api)")
	apiTokenPtr := flag.String("token", "", "Your API token")
	jiraProjectIDPtr := flag.String("jiraProjectID", "", "Your JIRA projectID (jiraProjectID or jiraProjectKey is required)")
	jiraProjectKeyPtr := flag.String("jiraProjectKey", "", "Your JIRA projectKey (jiraProjectID or jiraProjectKey is required)")
	jiraTicketTypePtr := flag.String("jiraTicketType", "Bug", "Optional. Chosen JIRA ticket type")
	severityPtr := flag.String("severity", "low", "Optional. Your severity threshold")
	maturityFilterPtr := flag.String("maturityFilter", "", "Optional. include only maturity level(s) separated by commas [mature,proof-of-concept,no-known-exploit,no-data]")
	typePtr := flag.String("type", "all", "Optional. Your issue type (all|vuln|license)")
	assigneeNamePtr := flag.String("assigneeName", "", "Optional. The Jira user ID to assign issues to. Note: Do not use assigneeName and assigneeId at the same time")
	assigneeIDPtr := flag.String("assigneeId", "", "Optional. The Jira user ID to assign issues to. Note: Do not use assigneeName and assigneeId at the same time")
	labelsPtr := flag.String("labels", "", "Optional. Jira ticket labels")
	priorityIsSeverityPtr := flag.Bool("priorityIsSeverity", false, "Use issue severity as priority")
	priorityScorePtr := flag.Int("priorityScoreThreshold", 0, "Optional. Your min priority score threshold [INT between 0 and 1000]")
	debugPtr := flag.Bool("debug", false, "Optional. enable debug mode")
	dryRunPtr := flag.Bool("dryRun", false, "Optional. create a file with all the tickets without open them on jira")

	flag.Parse()

	opt.mandatoryFlags.setMandatoryFlags(orgIDPtr, endpointAPIPtr, apiTokenPtr, jiraProjectIDPtr, jiraProjectKeyPtr)
	opt.optionalFlags.setoptionalFlags(projectIDPtr, jiraTicketTypePtr, severityPtr, maturityFilterPtr,
		typePtr, assigneeNamePtr, assigneeIDPtr, labelsPtr, priorityIsSeverityPtr, priorityScorePtr, debugPtr, dryRunPtr)

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
