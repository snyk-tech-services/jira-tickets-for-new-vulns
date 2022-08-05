package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func makeSnykAPIRequest(verb string, endpointURL string, snykToken string, body []byte, customDebug debug) ([]byte, error) {

	bodyBuffer := bytes.NewBuffer(nil)

	if verb == "POST" && body != nil {
		bodyBuffer = bytes.NewBuffer(body)
	}

	request, err := http.NewRequest(verb, endpointURL, bodyBuffer)
	if err != nil {
		customDebug.Debugf("*** ERROR *** could not create requests to '%s' failed with error %s\n", endpointURL, err.Error())
		return nil, err
	}

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

	var responseData []byte
	if response != nil {
		var er error
		responseData, er = ioutil.ReadAll(response.Body)
		if er != nil {
			customDebug.Debugf("*** ERROR *** could not read response from request to endpoint %s with error %s\n", endpointURL, err.Error())
		}
	}

	if err != nil || response == nil || response.StatusCode >= 300 {

		count := 0
		for {

			customDebug.Debugf("*** INFO *** Sending %s request to %s", verb, endpointURL)
			customDebug.Debugf("*** INFO *** retry number %d\n", count)

			response, err = client.Do(request)
			if err != nil {
				customDebug.Debugf("*** ERROR *** Request on endpoint '%s' failed with error %s, Retrying\n", endpointURL, err.Error())
			}

			// requests fails but we want to retry
			if response != nil {

				if response.StatusCode < 500 {
					if response.Body != nil {
						responseData, err = ioutil.ReadAll(response.Body)
						if err != nil {
							customDebug.Debugf("*** ERROR *** could not read response from request to endpoint %s with error %s\n", endpointURL, err.Error())
						}
					}

					break
				}

				if response.Body != nil {
					responseData, err = ioutil.ReadAll(response.Body)
					if err != nil {
						customDebug.Debugf("*** ERROR *** could not read response from request to endpoint %s with error %s\n", endpointURL, err.Error())
					}
				}
			}

			// Allow 2 retries with other error type then fail properly
			if count >= 2 {
				customDebug.Debugf("*** ERROR *** Request on endpoint '%s' failed too many times\n", endpointURL)
				customDebug.Debugf("*** ERROR *** Ticket for this issue cannot be created. Skipping\n")
				errorMessage := "*** ERROR *** Request on endpoint " + endpointURL + " failed too many times with 50x error\n" + "*** ERROR *** Ticket for this issue cannot be created. Skipping\n"
				// writing into the file
				writeErrorFile(errorMessage, customDebug)
				return nil, errors.New("Failed too many time with 50x errors") // skipping this
			}

			count = count + 1
			time.Sleep(1)
		}
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
	return responseData, err
}
