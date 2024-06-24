package main

// structure containing the debug flag to check on
type debug struct {
	PrintDebug bool
}

// Flags
// flags structures
// separated in 2 structure because some function needs only the mandatory
type flags struct {
	mandatoryFlags            MandatoryFlags
	optionalFlags             optionalFlags
	customMandatoryJiraFields map[string]interface{}
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
	projectCriticality     string
	projectEnvironment     string
	projectLifecycle       string
	jiraTicketType         string
	severity               string
	severityArray          string
	issueType              string
	maturityFilterString   string
	assigneeID             string
	labels                 string
	dueDate                string
	priorityIsSeverity     bool
	priorityScoreThreshold int
	debug                  bool
	dryRun                 bool
	cveInTitle             bool
	ifUpgradeAvailableOnly bool
	ifAutoFixableOnly      bool
}
