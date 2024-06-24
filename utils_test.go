package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
)

type mirroredResponse struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Token  string `json:"token"`
	Body   []byte `json:"body"`
}

/*
**
function removeLogFile
input: none
return path : string
find log file and return path
**
*/
func findLogFile(fileType string) (string, bool) {

	// list all file in the directory
	fileInfo, err := ioutil.ReadDir(".")
	if err != nil {
		log.Fatal()
	}

	// Look for the one starting with listOfTicketCreated or ErrorsFile
	path := "./"
	found := false
	for _, file := range fileInfo {
		if !file.IsDir() {
			if strings.HasPrefix(file.Name(), fileType) {
				path += file.Name()
				found = true
				break
			}
		}
	}

	return path, found
}

/*
**
function removeLogFile
input: none
return none
clean logs after test
**
*/
func removeLogFile() {

	// Find log file
	path, found := findLogFile("ErrorsFile")

	if found {
		// Delete the file created for the test
		e := os.Remove(path)
		if e != nil {
			log.Fatal(e)
		}
	}

	path, found = findLogFile("listOfTicketCreated")

	if found {
		// Delete the file created for the test
		e := os.Remove(path)
		if e != nil {
			log.Fatal(e)
		}
	}

	return
}

// HTTPResponseStubAndMirrorRequest Stubbing HTTP response
func HTTPResponseStubAndMirrorRequest(url string, method string, token string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		body, _ := ioutil.ReadAll(r.Body)

		if r.Method == "POST" && len(body) == 0 {
			log.Fatal("Missing Body on POST request")
		} else if r.Method == "GET" && len(body) > 0 {
			log.Fatal("Unexpected body in GET request")
		}

		resp := &mirroredResponse{
			URL:    r.RequestURI,
			Method: r.Method,
			Token:  r.Header.Get("Authorization"),
			Body:   body,
		}
		marshalledResp, _ := json.Marshal(resp)
		w.Write(marshalledResp)
	}))
}

// HTTPResponseCheckAndStub Check url match and Stubbing HTTP response
func HTTPResponseCheckAndStub(url string, testType string) *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.RequestURI != url {
			resp = []byte("404 - url mismatch")
		} else {
			resp = readFixture("./fixtures/" + testType + ".json")
		}

		w.Write(resp)
	}))
}

// HTTPResponseCheckAndStubError Check url match and Stubbing HTTP response
func HTTPResponseCheckAndStubError(url string, testType string) *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		fmt.Println("Error case")
		w.WriteHeader(400)
		resp = []byte("400 - Bad Request error ")
		count++

		w.Write(resp)
	}))
}

// HTTPResponseCheckAndStub Check url match and Stubbing HTTP response
func HTTPResponseCheckAndStub_() *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if "/v1/org/123/project/123/issue/SNYK-JS-PACRESOLVER-1564857/paths" == r.RequestURI {
			resp = readFixture("./fixtures/issuePACRESOLVERPath.json")
		} else if "/v1/org/123/project/123/issue/SNYK-JS-DOTPROP-543489/paths" == r.RequestURI {
			resp = readFixture("./fixtures/issueJSDOTPath.json")
		} else if "/v1/org/123/project/123/issue/SNYK-JS-ACORN-559469/paths" == r.RequestURI {
			resp = readFixture("./fixtures/issueACORNPath.json")
		} else if "/v1/org/123/project/123/aggregated-issues" == r.RequestURI {
			resp = readFixture("./fixtures/projectAggregatedIssuesPerPath.json")
		} else if "/v1/org/456/project/456/aggregated-issues" == r.RequestURI {
			resp = readFixture("./fixtures/projectAggregatedIssuesPerPathLicense.json")
		} else if "/v1/org/456/project/456/issue/snyk:lic:npm:goof:GPL-2.0/paths" == r.RequestURI {
			resp = readFixture("./fixtures/licensePath.json")
		} else {
			resp = []byte("404 - url mismatch")
		}

		w.Write(resp)
	}))
}

// HTTPResponseCheckAndStub Check url match and Stubbing HTTP response
func HTTPResponseCheckAndStubWithError_() *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if "/v1/org/123/project/123/issue/SNYK-JS-PACRESOLVER-1564857/paths" == r.RequestURI {
			resp = readFixture("./fixtures/issuePACRESOLVERPath.json")
		} else if "/v1/org/123/project/123/issue/SNYK-JS-DOTPROP-543489/paths" == r.RequestURI {
			resp = readFixture("./fixtures/issueJSDOTPath.json")
		} else if "/v1/org/123/project/123/issue/SNYK-JS-ACORN-559469/paths" == r.RequestURI {
			resp = readFixture("./fixtures/issueACORNPath.json")
		} else if "/v1/org/123/project/123/issue/SNYK-JS-ACORN-559470/paths" == r.RequestURI {
			resp = []byte("500 - internal server error")
		} else if "/v1/org/123/project/123/aggregated-issues" == r.RequestURI {
			resp = readFixture("./fixtures/projectAggregatedIssuesPerPathWith500Error.json")
		} else {
			resp = []byte("404 - url mismatch")
		}

		w.Write(resp)
	}))
}

// HTTPResponseCheckAndStub Check url match and Stubbing HTTP response
func HTTPResponseCheckAndStubNoVulnOrLicense() *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if "/v1/org/123/project/123/aggregated-issues" == r.RequestURI {
			resp = readFixture("./fixtures/projectAggregatedIssuesPerPathnoVulnOrLicenseIssue.json")
		} else {
			resp = []byte("404 - url mismatch")
		}

		w.Write(resp)
	}))
}

// HTTPResponseStub Stubbing HTTP response
func HTTPResponseCheckOpenJiraTickets(url string) *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.RequestURI != url {
			resp = []byte("404 - url mismatch")
		} else {
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse.json")
		}

		w.Write(resp)
	}))
}

// HTTPResponseStub Stubbing HTTP response
func HTTPResponseCheckOpenJiraTicketsWithError(url string) *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		body, er := ioutil.ReadAll(r.Body)

		if er != nil {
			log.Fatal(er)
		}

		if r.RequestURI != url {
			resp = []byte("404 - url mismatch")
		} else if strings.Contains(string(body), "priority") == true {
			fmt.Println("Error case")
			w.WriteHeader(http.StatusUnprocessableEntity)
			resp = readFixture("./fixtures/singleJiraTicketOpeningErrorResponse.json")
		} else {
			fmt.Println("Working case")
			w.WriteHeader(http.StatusAccepted)
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse.json")
		}

		w.Write(resp)
	}))
}

var count int = 0

func HTTPResponseCheckOpenJiraTicketsWithError50x(url string) *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if count >= 2 {
			fmt.Println("Working case")
			w.WriteHeader(http.StatusAccepted)
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse.json")
		} else if count == 1 {
			fmt.Println("Error case no status")
			resp = nil
			count++
		} else {
			fmt.Println("Error case")
			w.WriteHeader(503)
			resp = []byte("503 - Service Unavailable")
			count++
		}

		fmt.Println(string(resp))
		w.Write(resp)
	}))
}

// HTTPResponseStub Stubbing HTTP response
func HTTPResponseCheckOpenJiraMultipleTicketsWithError() *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		body, er := ioutil.ReadAll(r.Body)

		if er != nil {
			log.Fatal(er)
		}

		if strings.Contains(string(body), "priority") == true {
			fmt.Println("Error case")
			w.WriteHeader(http.StatusUnprocessableEntity)
			resp = readFixture("./fixtures/singleJiraTicketOpeningErrorResponse.json")
		} else if r.RequestURI == "/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue" {
			fmt.Println("Working case")
			w.WriteHeader(http.StatusAccepted)
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse.json")
		} else if r.RequestURI == "/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559765/jira-issue" {
			fmt.Println("Working case")
			w.WriteHeader(http.StatusAccepted)
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse2.json")
		} else if r.RequestURI == "/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559766/jira-issue" {
			fmt.Println("Working case")
			w.WriteHeader(http.StatusAccepted)
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse3.json")
		}

		w.Write(resp)
	}))
}

func HTTPResponseCheckOpenJiraMultipleTickets() *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.RequestURI == "/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue" {
			fmt.Println("Working case")
			w.WriteHeader(http.StatusAccepted)
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse.json")
		} else if r.RequestURI == "/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559766/jira-issue" {
			fmt.Println("Working case")
			w.WriteHeader(http.StatusAccepted)
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse3.json")
		}

		w.Write(resp)
	}))
}

func HTTPResponseCheckOpenJiraMultipleTicketsWithErrorTwice() *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		body, er := ioutil.ReadAll(r.Body)

		if er != nil {
			log.Fatal(er)
		}

		if strings.Contains(string(body), "priority") == true {
			fmt.Println("First Error")
			w.WriteHeader(http.StatusUnprocessableEntity)
			resp = readFixture("./fixtures/singleJiraTicketOpeningErrorResponse.json")
		} else if r.RequestURI == "/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559764/jira-issue" {
			fmt.Println("Second Error")
			w.WriteHeader(http.StatusUnprocessableEntity)
		} else if r.RequestURI == "/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559765/jira-issue" {
			fmt.Println("Working case")
			w.WriteHeader(http.StatusAccepted)
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse2.json")
		} else if r.RequestURI == "/v1/org/123/project/12345678-1234-1234-1234-123456789012/issue/SNYK-JS-MINIMIST-559766/jira-issue" {
			fmt.Println("Working case")
			w.WriteHeader(http.StatusAccepted)
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse3.json")
		}

		w.Write(resp)
	}))
}

func HTTPResponseCheckOpenJiraMultipleTicketsFailure() *httptest.Server {
	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.RequestURI == "" {
			resp = []byte("404 - url mismatch")
		} else {
			//fmt.Println("Error")
			w.WriteHeader(http.StatusUnprocessableEntity)
			resp = readFixture("./fixtures/singleJiraTicketOpeningErrorResponse.json")
		}

		w.Write(resp)
	}))
}

func HTTPResponseEndToEnd() *httptest.Server {

	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if string(r.RequestURI) == "/rest/orgs/123/projects?version=2022-07-08~beta&status=active&limit=100" {
			resp = readFixture("./fixtures/orgEndToEnd.json")

		} else if r.RequestURI == "/v1/org/123/project/123" {

			resp = readFixture("./fixtures/ProjectsForEndToEnd.json")

		} else if r.RequestURI == "/v1/org/123/project/123/jira-issues" {

			resp = readFixture("./fixtures/existingJiraTickets.json")

		} else if r.RequestURI == "/v1/org/123/project/123/aggregated-issues" {

			resp = readFixture("./fixtures/projectAggregatedIssuesPerPath.json")

		} else if "/v1/org/123/project/123/issue/SNYK-JS-PACRESOLVER-1564857/paths" == r.RequestURI {

			resp = readFixture("./fixtures/issuePACRESOLVERPath.json")

		} else if "/v1/org/123/project/123/issue/SNYK-JS-DOTPROP-543489/paths" == r.RequestURI {

			resp = readFixture("./fixtures/issueJSDOTPath.json")

		} else if "/v1/org/123/project/123/issue/SNYK-JS-ACORN-559469/paths" == r.RequestURI {

			resp = readFixture("./fixtures/issueACORNPath.json")

		} else if r.RequestURI == "/v1/org/123/project/123/issue/SNYK-JS-PACRESOLVER-1564857/jira-issue" {

			resp = readFixture("./fixtures/singleJiraTicketOpeningResponseEndToEndPACRESOLVER.json")

		} else if r.RequestURI == "/v1/org/123/project/123/issue/SNYK-JS-DOTPROP-543489/jira-issue" {

			resp = readFixture("./fixtures/singleJiraTicketOpeningResponseEndToEndJSDOT.json")

		} else if r.RequestURI == "/v1/org/123/project/123/issue/SNYK-JS-ACORN-559469/jira-issue" {

			resp = readFixture("./fixtures/singleJiraTicketOpeningResponseEndToEndACORN.json")

		} else {
			fmt.Println("Error while mocking request", r.URL)
		}

		w.WriteHeader(http.StatusOK)
		w.Write(resp)

	}))

}

func HTTPResponseRestPagination() *httptest.Server {

	var resp []byte
	var status = http.StatusOK
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if string(r.RequestURI) == "/rest/orgs/xyz-paging/projects?version=2022-07-08~beta&status=active" {
			resp = readFixture("./fixtures/rest_pagination1.json")

		} else if r.RequestURI == "/orgs/408fbcd1-2b1d-4892-a0b4-48cb3908c50d/projects?version=2022-07-08~beta&status=active&limit=10&starting_after=test-get-page2" {

			resp = readFixture("./fixtures/rest_pagination2.json")

		} else if r.RequestURI == "/orgs/408fbcd1-2b1d-4892-a0b4-48cb3908c50d/projects?version=2022-07-08~beta&status=active&limit=10&starting_after=test-get-page3" {

			resp = readFixture("./fixtures/rest_pagination3.json")
			
		} else {
			fmt.Println("Error while mocking request", r.URL)
			status = http.StatusNotFound
		}

		w.WriteHeader(status)
		w.Write(resp)

	}))

}

// HTTPResponseStubAndMirrorRequest Stubbing HTTP response
func HTTPResponseStubAndMirrorCodeRequest() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		body, _ := ioutil.ReadAll(r.Body)

		if r.Method == "POST" && len(body) == 0 {
			log.Fatal("Missing Body on POST request")
		} else if r.Method == "GET" && len(body) > 0 {
			log.Fatal("Unexpected body in GET request")
		}

		resp := &mirroredResponse{
			URL:    r.RequestURI,
			Method: r.Method,
			Token:  r.Header.Get("Authorization"),
			Body:   body,
		}
		marshalledResp, _ := json.Marshal(resp)
		w.Write(marshalledResp)
	}))
}

func readFixture(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return data
}

// In the REST api tests, we just want the data array, not the full fixture.
type Fixture struct {
	Data json.RawMessage `json:"data"`
}

func readFixtureData(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("failed reading file: %s", err)
	}

	var fixture Fixture

	err = json.Unmarshal(data, &fixture)
	if err != nil {
		log.Fatalf("failed unmarshalling json: %s", err)
	}

	return fixture.Data
}

func HTTPResponseCodeIssueStubAndMirrorRequest() *httptest.Server {

	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI == "" {
			resp = []byte("404 - url mismatch")
		} else if r.RequestURI == "/v1/org/123/project/456/issue/xxbac5ed-83dd-xx65-8730-2xxx4467e00d/jira-issue" {
			resp = readFixture("./fixtures/snyk_code_fixtures/results/singleCodeJiraTicketOpeningResponse")
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=456&version=2021-08-20~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeData.json")
		} else if r.RequestURI == "/rest/orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues?project_id=1234&severity=high&version=2021-08-20~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataHighIssuesWithPaginationPage1.json")
		} else if r.RequestURI == "/rest/orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues?project_id=1234&severity=critical&version=2021-08-20~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataCriticalIssuesWithPaginationPage1.json")
		} else if r.RequestURI == "/rest/orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues?project_id=1234&version=2021-08-20~experimental&severity=critical&starting_after=v1.eyJpZCI6Mz1zODQyMH0%3D" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataCriticalIssuesWithPaginationPage2.json")
		} else if r.RequestURI == "/rest//orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues?project_id=1234&version=2021-08-20~experimental&severity=critical&starting_after=v1.eyJpZCI6Mz1zODQyMH0%3D" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataCriticalIssuesWithPaginationPage3.json")
		} else if r.RequestURI == "/rest/orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues?project_id=1234&version=2021-08-20~experimental?limit=10&severity=critical&starting_after=v1.eyJwcmlvcml0eVNjb3JlIjo1NTgsImlkIjoiNjU5MDc3Mjg1In0%3D" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataCriticalIssuesWithPaginationPage3.json")
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=1234&version=2021-08-20~experimental?limit=10&starting_after=v1.eyJpZCI6Mz1zODQyMH0%3D" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeData.json")
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=789&severity=low&version=2021-08-20~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataLowIssues.json")
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=789&severity=high&version=2021-08-20~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataHighIssues.json")
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=789&severity=critical&version=2021-08-20~experimental" {
			w.WriteHeader(http.StatusNotFound)
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=7891&severity=low&version=2021-08-20~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataLowIssues.json")
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=7891&severity=high&version=2021-08-20~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataHighIssuesIgnored.json")
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=7891&severity=critical&version=2021-08-20~experimental" {
			w.WriteHeader(http.StatusNotFound)
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=1234&severity=high&version=2021-08-20~experimental" {
			w.WriteHeader(http.StatusNotFound)
		} else if r.RequestURI == "/rest/orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues?project_id=1234&severity=medium&version=2021-08-20~experimental" {
			w.WriteHeader(http.StatusNotFound)
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=1234&severity=low&version=2021-08-20~experimental" {
			w.WriteHeader(http.StatusNotFound)
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=789&severity=medium&version=2021-08-20~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataMediumIssues.json")
		} else if r.RequestURI == "/rest/orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues?project_id=1234&severity=low&version=2021-08-20~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataEmpty.json")
		} else if r.RequestURI == "/rest/orgs/123/issues?project_id=7891&severity=medium&version=2021-08-20~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeDataMediumIssues.json")
		} else if r.RequestURI == "/rest/orgs/123/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e00d?project_id=456&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetails.json")
		} else if r.RequestURI == "/rest/orgs/123/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e00d?project_id=1234&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetails.json")
		} else if r.RequestURI == "/rest/orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e00q?project_id=1234&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetailsForPagination.json")
		} else if r.RequestURI == "/rest/orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues/detail/code/xxbac5ed-critical2-xx65-8730-2xxx4467e00q?project_id=1234&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetailsForPagination.json")
		} else if r.RequestURI == "/rest/orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues/detail/code/xxbac5ed-critical1-xx65-8730-2xxx4467e00q?project_id=1234&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetailsForPagination.json")
		} else if r.RequestURI == "/rest/orgs/xxx99a85-c519-xxxx-ae55-xxx9b9bfaxxx/issues/detail/code/bbbbbbb-83dd-xx65-8730-2xxx4467e00q?project_id=1234&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetailsForPagination.json")
		} else if r.RequestURI == "/rest/orgs/123/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e0xx?project_id=456&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetails2.json")
		} else if r.RequestURI == "/rest/orgs/123/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e0zz?project_id=456&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetails3.json")
		} else if r.RequestURI == "/v1/org/123/project/456/issue/SNYK-JS-MINIMIST-559764/jira-issue" {
			resp = readFixture("./fixtures/singleJiraTicketOpeningResponse.json")
		} else if r.RequestURI == "/rest/orgs/123/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e00d?project_id=789&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetails.json")
		} else if r.RequestURI == "/rest/orgs/123/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e0xx?project_id=789&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetails2.json")
		} else if r.RequestURI == "/rest/orgs/123/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e0zz?project_id=789&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetails3.json")
		} else if r.RequestURI == "/rest/orgs/123/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e00d?project_id=7891&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetailsWithIgnore.json")
		} else if r.RequestURI == "/rest/orgs/123/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e0xx?project_id=7891&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetails2.json")
		} else if r.RequestURI == "/rest/orgs/123/issues/detail/code/xxbac5ed-83dd-xx65-8730-2xxx4467e0zz?project_id=7891&version=2022-04-06~experimental" {
			resp = readFixture("./fixtures/snyk_code_fixtures/snykCodeIssueDetails3.json")
		} else {
			fmt.Println("**** TEST ERROR *** Could not match URL", r.RequestURI)
			log.Fatal()
		}

		w.Write(resp)
	}))

}
