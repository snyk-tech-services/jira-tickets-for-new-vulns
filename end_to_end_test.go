package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEndToEndFunc(t *testing.T) {

	os.Setenv("EXECUTION_ENVIRONMENT", "test")

	server := HTTPResponseEndToEnd()
	defer server.Close()

	// reset command line arg
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = append(os.Args, "--orgID=123")
	os.Args = append(os.Args, "--token=123")
	os.Args = append(os.Args, "--jiraProjectID=123")
	os.Args = append(os.Args, "--api="+server.URL)

	// Keeping the line below => useful for debug but print too many things
	// os.Args = append(os.Args, "-debug=true")

	// Get the console output
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	main()

	// Test finished, read the output and compare with expectation
	w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	// Checking the log file
	path, found := findLogFile("listOfTicketCreated")

	assert.FileExists(t, path)
	assert.True(t, found)

	// check if the json is valid
	file, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	var unmarshalledFile interface{}
	assert.Equal(t, json.Unmarshal(file, &unmarshalledFile), nil)

	// Delete the file created for the test
	removeLogFile()

	os.Args = oldArgs

	compare := strings.Contains(string(out), "Number of tickets created: 3")

	assert.Equal(t, compare, true)
}

// comment for now, error with the arguments that are redefined
// Probably need a clear somewhere in the previous TestEndToEndFunc

// func TestEndToEndDryRunFunc(t *testing.T) {

// 	server := HTTPResponseEndToEnd()
// 	defer server.Close()

// 	fmt.Println(os.Args)

// 	os.Args = append(os.Args, "-orgID=123")
// 	os.Args = append(os.Args, "-token=123")
// 	os.Args = append(os.Args, "-jiraProjectID=123")
// 	os.Args = append(os.Args, "-api="+server.URL)
// 	os.Args = append(os.Args, "-dryRun=true")

// 	// Get the console output
// 	rescueStdout := os.Stdout
// 	r, w, _ := os.Pipe()
// 	os.Stdout = w

// 	main()

// 	os.Args = []string{}

// 	// Test finished, read the output and compare with expectation
// 	w.Close()
// 	out, _ := ioutil.ReadAll(r)
// 	os.Stdout = rescueStdout

// 	compare := strings.Contains(string(out), "Number of tickets created: 0")
// 	dryRunResult := strings.Contains(string(out), "Dry run result can be found in .log file")

// 	// Delete the file created for the test
// 	removeLogFile()

// 	assert.Equal(t, compare, true)
// 	assert.Equal(t, dryRunResult, true)

// }
