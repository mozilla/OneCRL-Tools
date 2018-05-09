build:
	chmod +x scheduler.py
	# will need to set $GOPATH and $GOBIN for below "go get" to work
	go get ../../salesforce2OneCRL
	zip -jr ccadb_scheduler.zip scheduler.py .config.yml $(GOPATH)/bin/salesforce2OneCRL
clean:
	rm ccadb_scheduler.zip
.PHONY: clean build
