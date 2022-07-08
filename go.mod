module github.com/mozilla/OneCRL-Tools

go 1.14

require (
	github.com/gocarina/gocsv v0.0.0-20200330101823-46266ca37bd3
	github.com/jcjones/constraintcrypto v0.0.0-20181102151840-8bf88cbc6c7c
	github.com/joho/godotenv v1.3.0
	github.com/mattn/go-sqlite3 v1.14.0
	github.com/mitchellh/mapstructure v1.3.3
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.6.0
	github.com/tdewolff/minify v2.3.6+incompatible
	github.com/tdewolff/parse v2.3.4+incompatible // indirect
	github.com/tdewolff/test v1.0.6 // indirect
	github.com/termie/go-shutil v0.0.0-20140729215957-bcacb06fecae
	github.com/wellington/go-libsass v0.9.2
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
	golang.org/x/sys v0.0.0-20220708085239-5a0f0661e09d // indirect
	gopkg.in/yaml.v2 v2.3.0
)

replace github.com/mozilla/OneCRL-Tools v0.0.0-20200707043610-3371182b2d48 => ./
