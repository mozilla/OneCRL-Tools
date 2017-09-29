build:
	chmod +x scheduler.py
	go get -u github.com/mozilla/OneCRL-Tools/salesforce2OneCRL
	zip -jr ccadb_scheduler.zip scheduler.py .config.yml $(GOPATH)/bin/salesforce2OneCRL
clean:
	rm ccadb_scheduler.zip
.PHONY: clean build
