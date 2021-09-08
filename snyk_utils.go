package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

func makeSnykAPIRequest(verb string, endpointURL string, snykToken string, body []byte) []byte {
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
		fmt.Print(err.Error())
		os.Exit(1)
	}

	if response.StatusCode == 404 {
		fmt.Printf("Resource not found for %s", endpointURL)
		os.Exit(1)
	} else if response.StatusCode == 422 {
		fmt.Printf("Error %d, Unprocessable Entity\n", response.StatusCode)
	} else if response.StatusCode > 400 {
		fmt.Printf("Unexpected response %d\n", response.StatusCode)
		os.Exit(1)
	}

	responseData, err := ioutil.ReadAll(response.Body)

	if err != nil {
		if strings.Contains(string(responseData), "priority") {
			fmt.Println(err)
			fmt.Println("retrying without the priority field")
		} else {
			log.Fatal(err)
		}
	}
	return responseData
}
