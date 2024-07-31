package main

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

type Repo struct {
	Org         string `dynamodbav:"org"`
	Backlog     string `dynamodbav:"backlog"`
	ValueStream string `dynamodbav:"value_stream"`
	Manager     string `dynamodbav:"manager"`
	TeamOwner   string `dynamodbav:"team_owner"`
	Name        string `dynamidbav:"name"`
}

const REPO_TABLE_NAME = "gpp-prod-repos"

func getRepos() (map[string]Repo, error) {
	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithSharedConfigProfile("legacy-security"),
	)
	if err != nil {
		log.Fatalf("Unable to load SDK config, %v", err)
		return nil, err
	}

	// Using the Config value, create the DynamoDB client
	svc := dynamodb.NewFromConfig(cfg)
	resp, err := svc.Scan(ctx, &dynamodb.ScanInput{
		TableName: aws.String(REPO_TABLE_NAME),
	})
	if err != nil {
		log.Fatalf("failed to list items from '%s', %v", REPO_TABLE_NAME, err)
		return nil, err
	}

	var pRepos []Repo
	err = attributevalue.UnmarshalListOfMaps(resp.Items, &pRepos)
	if err != nil {
		log.Fatalf("failed to list tables, %v", err)
		return nil, err
	}

	// create a map indexed by full repo name
	m := make(map[string]Repo)
	for _, r := range pRepos {
		m[r.Org+"/"+r.Name] = r
	}
	return m, nil
}
