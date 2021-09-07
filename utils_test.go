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

func readFixture(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return data
}
