package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
)

// HTTPResponseStub Stubbing HTTP response
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

func readFixture(path string) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return data
}
