mkdir dist
env GOOS=darwin GOARCH=amd64 go build -o dist/snyk-jira-sync-macos *.go
env GOOS=linux GOARCH=amd64 go build -o dist/snyk-jira-sync-linux *.go
env GOOS=windows GOARCH=amd64 go build -o dist/snyk-jira-sync-win.exe *.go
