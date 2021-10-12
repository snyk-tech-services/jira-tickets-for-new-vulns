package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
)

type mirroredResponse struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Token  string `json:"token"`
	Body   []byte `json:"body"`
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
			fmt.Println("Error")
			w.WriteHeader(http.StatusUnprocessableEntity)
			resp = readFixture("./fixtures/singleJiraTicketOpeningErrorResponse.json")
		}

		w.Write(resp)
	}))
}

func HTTPResponseEndToEnd() *httptest.Server {

	var resp []byte
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if string(r.RequestURI) == "/v1/org/123/projects" {

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

func readFixture(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return data
}
