package main

// structure containing the debug flag to check on
type debug struct {
	PrintDebug bool
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
	ifUpgradeAvailableOnly bool
}

type snyk struct {
	OrgID                  string `yaml:"orgID"`
	Severity               string `yaml:"severity"`
	MaturityFilter         string `yaml:"maturityFilter"`
	IssueType              string `yaml:"type"`
	PriorityScoreThreshold int    `yaml:"priorityScoreThreshold"`
	RemoteUrl              string `yaml:"remoteUrl"`
	ProjectID              string `yaml:"projectID"`
	IfUpgradeAvailableOnly bool   `yaml:"ifUpgradeAvailableOnly"`
	EndpointAPI            string `yaml:"api"`
}

type jira struct {
	JiraTicketType string `yaml:"jiraTicketType"`
	JiraProjectID  string `yaml:"jiraProjectID"`
	JiraProjectKey string `yaml:"jiraProjectKey"`
	AssigneeId     string `yaml:"assigneeId"`
	AssigneeName   string `yaml:"assigneeName"`
	Labels         string `yaml:"labels"`

	// labels:
	//    - <IssueLabel1>
	//    - <IssueLabel2>
	PriorityIsSeverity bool `yaml:"priorityIsSeverity"`
	// severityToPriorityMapping:
	//     critical: "Highest"
	//     high: "High"
	//     medium: "Medium"
	//     low: "Low"
}

type config struct {
	Snyk snyk `yaml:"snyk"`
	Jira jira `yaml:"jira"`
}
