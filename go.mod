module github.com/mozilla/OneCRL-Tools

go 1.14

require (
	github.com/PuerkitoBio/goquery v1.5.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20200330101823-46266ca37bd3
	github.com/google/certificate-transparency-go v1.1.4 // indirect
	github.com/jcjones/constraintcrypto v0.0.0-20181102151840-8bf88cbc6c7c
	github.com/joho/godotenv v1.3.0
	github.com/mattn/go-sqlite3 v1.14.15
	github.com/mitchellh/mapstructure v1.4.1
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/tdewolff/minify v2.3.6+incompatible
	github.com/tdewolff/parse v2.3.4+incompatible // indirect
	github.com/tdewolff/test v1.0.6 // indirect
	github.com/termie/go-shutil v0.0.0-20140729215957-bcacb06fecae
	github.com/wellington/go-libsass v0.9.2
	golang.org/x/crypto v0.0.0-20220411220226-7b82a4e95df4
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/mozilla/OneCRL-Tools v0.0.0-20200707043610-3371182b2d48 => ./
