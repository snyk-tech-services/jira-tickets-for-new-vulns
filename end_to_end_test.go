package main

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEndToEndFunc(t *testing.T) {

	server := HTTPResponseEndToEnd()
	defer server.Close()

	os.Args = append(os.Args, "-orgID=123")
	os.Args = append(os.Args, "-token=123")
	os.Args = append(os.Args, "-jiraProjectID=123")
	os.Args = append(os.Args, "-api="+server.URL)

	// Get the console output
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	main()

	// Test finished, read the output and compare with expectation
	w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	println(string(out))

	compare := strings.Contains(string(out), "Number of tickets created: 3")

	assert.Equal(t, compare, true)

}

func TestEndToEndDryRunFunc(t *testing.T) {

	server := HTTPResponseEndToEnd()
	defer server.Close()

	os.Args = append(os.Args, "-orgID=123")
	os.Args = append(os.Args, "-token=123")
	os.Args = append(os.Args, "-jiraProjectID=123")
	os.Args = append(os.Args, "-api="+server.URL)
	os.Args = append(os.Args, "-dryRun=true")

	// Get the console output
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	main()

	// Test finished, read the output and compare with expectation
	w.Close()
	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout

	println(string(out))

	compare := strings.Contains(string(out), "Number of tickets created: 0")
	dryRunResult := strings.Contains(string(out), "Dry run result can be found in .log file")

	assert.Equal(t, compare, true)
	assert.Equal(t, dryRunResult, true)

}
