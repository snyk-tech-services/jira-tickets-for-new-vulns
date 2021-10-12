package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

func makeSnykAPIRequest(verb string, endpointURL string, snykToken string, body []byte) ([]byte, error) {

	bodyBuffer := bytes.NewBuffer(nil)

	if verb == "POST" && body != nil {
		bodyBuffer = bytes.NewBuffer(body)
	}

	request, _ := http.NewRequest(verb, endpointURL, bodyBuffer)

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "token "+snykToken)

	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		fmt.Printf("Request on endpoint '%s' failed with error %s\n", endpointURL, err.Error())
		return nil, errors.New("Request failed")
	}

	responseData, err := ioutil.ReadAll(response.Body)

	if response.StatusCode == 404 {
		fmt.Printf("Request on endpoint '%s' failed with error %s\n", endpointURL, response.Status)
		return nil, errors.New("Request failed")
	} else if response.StatusCode == 422 {
		fmt.Printf("Request on endpoint '%s' failed with error %s\n", endpointURL, response.Status)
		fmt.Printf("Details : %s\n", string(responseData))
		fmt.Printf("Requests body : %s\n", string(body))
		return nil, errors.New("Request failed")
	} else if response.StatusCode > 400 {
		fmt.Printf("Request on endpoint '%s' failed with error %s\n", endpointURL, response.Status)
		fmt.Printf("Details : %s\n", string(responseData))
		fmt.Printf("Requests body : %s\n", string(body))
		return nil, errors.New("Request failed")
	}

	if err != nil {
		if strings.Contains(strings.ToLower(string(responseData)), "error") {
			fmt.Println(err)
			fmt.Println("Retrying without the priority field")
		}
		return nil, errors.New("Request failed")
	}
	return responseData, nil
}
