package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

func makeSnykAPIRequest(verb string, endpointURL string, snykToken string, body []byte, customDebug debug) ([]byte, error) {

	bodyBuffer := bytes.NewBuffer(nil)

	if verb == "POST" && body != nil {
		bodyBuffer = bytes.NewBuffer(body)
	}

	request, _ := http.NewRequest(verb, endpointURL, bodyBuffer)

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "token "+snykToken)
	request.Header.Set("User-Agent", "tech-services/snyk-jira-tickets-for-new-vulns")

	client := &http.Client{}
	response, err := client.Do(request)

	if err != nil {
		customDebug.Debugf("*** ERROR *** Request on endpoint '%s' failed with error %s\n", endpointURL, err.Error())
	}

	customDebug.Debugf("*** INFO *** Sending %s request to %s", verb, endpointURL)
	if body != nil {
		customDebug.Debug("*** INFO *** Body : ", string(body))
	}

	responseData, err := ioutil.ReadAll(response.Body)

	count := 0

	for ok := true; ok; ok = (response.StatusCode >= 500 && count < 3) {

		customDebug.Debugf("*** INFO *** Sending %s request to %s", verb, endpointURL)
		customDebug.Debugf("*** INFO *** retry number %d\n", count)

		response, err = client.Do(request)

		if err != nil {
			customDebug.Debugf("*** ERROR *** Request on endpoint '%s' failed with error %s, Retrying\n", endpointURL, err.Error())
		}

		if body != nil {
			customDebug.Debug("*** INFO *** Body : ", string(body))
		}

		if response.StatusCode >= 500 && count >= 2 {
			customDebug.Debugf("*** ERROR *** Request on endpoint '%s' failed too many times\n", endpointURL)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		responseData, err = ioutil.ReadAll(response.Body)
		count++
		time.Sleep(1)
	}

	if response.StatusCode == 404 {
		customDebug.Debugf("*** INFO *** Request on endpoint '%s' failed with error %s\n", endpointURL, response.Status)
		return nil, errors.New("Not found, Request failed")
	} else if response.StatusCode == 422 {
		customDebug.Debugf("*** INFO *** Request on endpoint '%s' failed with error %s\n", endpointURL, response.Status)
		customDebug.Debugf("*** INFO *** Please check that all expected fields are present in the config file\n")
		customDebug.Debugf("*** INFO *** Details : %s\n", string(responseData))
		return nil, errors.New("Unprocessable Entity, Request failed")
	} else if response.StatusCode > 400 {
		customDebug.Debugf("*** INFO *** Request on endpoint '%s' failed with error %s\n", endpointURL, response.Status)
		customDebug.Debugf("*** INFO *** Please check that all expected fields are present in the config file\n")
		customDebug.Debugf("*** INFO *** Details : %s\n", string(responseData))
		return nil, errors.New("Request failed")
	}

	if err != nil {
		if strings.Contains(strings.ToLower(string(responseData)), "error") {
			customDebug.Debug(err)
			customDebug.Debug("*** INFO *** Retrying without the priority field")
		}
		return nil, errors.New("Request failed")
	}
	time.Sleep(1)
	return responseData, nil
}
