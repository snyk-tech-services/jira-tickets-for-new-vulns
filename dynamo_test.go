package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDynamoFunc(t *testing.T) {
	assert := assert.New(t)
	repos, err := getRepos("", "")
	assert.Nil(err)
	assert.True(len(repos) > 0)
}
