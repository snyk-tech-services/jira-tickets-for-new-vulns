package main

import (
	"encoding/json"
	"testing"

	"github.com/michael-go/go-jsn/jsn"

	"github.com/stretchr/testify/assert"
)

// Test MakeSnykRequest function

//makeSnykAPIRequest(verb string, endpointURL string, snykToken string, body []byte) []byte

func TestMakeSnykRequestFunc(t *testing.T) {
	// should use the verb, the token, the url, and the body if POST
	// return the body we send to check it works as expected

	dummyBody := `{ test: test }`
	dummyBodyMarshalled, _ := json.Marshal(dummyBody)
	expectedTestURL := "/v1/org/123/project/123"
	expectedGETMethod := "GET"
	expectedPOSTMethod := "POST"
	expectedToken := "123"
	expectedPOSTResponse :=
		`{
  "body": "InsgdGVzdDogdGVzdCB9Ig==",
  "method": "POST",
  "token": "token 123",
  "url": "/v1/org/123/project/123"
}`

	expectedGETResponse :=
		`{
  "body": "",
  "method": "GET",
  "token": "token 123",
  "url": "/v1/org/123/project/123"
}`

	assert := assert.New(t)

	// TESTING POST

	server := HTTPResponseStubAndMirrorRequest(expectedTestURL, expectedPOSTMethod, expectedToken)

	defer server.Close()

	response := makeSnykAPIRequest(expectedPOSTMethod, server.URL+expectedTestURL, expectedToken, dummyBodyMarshalled)

	var unmarshalledResp map[string]interface{}
	json.Unmarshal(response, &unmarshalledResp)

	jsonResponse, _ := jsn.NewJson(unmarshalledResp)
	assert.Equal(expectedPOSTResponse, jsonResponse.Pretty())

	// TESTING GET
	server = HTTPResponseStubAndMirrorRequest(expectedTestURL, expectedGETMethod, expectedToken)

	defer server.Close()

	response = makeSnykAPIRequest(expectedGETMethod, server.URL+expectedTestURL, expectedToken, nil)

	json.Unmarshal(response, &unmarshalledResp)

	jsonResponse, _ = jsn.NewJson(unmarshalledResp)
	assert.Equal(expectedGETResponse, jsonResponse.Pretty())

	return
}
