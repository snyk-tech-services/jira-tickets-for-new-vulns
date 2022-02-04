package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
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
		return nil, errors.New("Request failed")
	}

	customDebug.Debugf("*** INFO *** Sending %s request to %s", verb, endpointURL)
	if body != nil {
		customDebug.Debug("*** INFO *** Body : ", string(body))
	}

	responseData, err := ioutil.ReadAll(response.Body)

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
	return responseData, nil
}
