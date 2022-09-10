# scan-deps

### Project Overview:

This project was developed by Mohd Yasreeb Hussain & Syed Adil Shariq to help the cybersecurity community.

## Quick Start

### Prerequisites
* Go

### Getting Started
```
$ git clone https://github.com/shariq027/scan-deps.git
$ cd scan-deps
$ go run main.go
```

## Usage

The above run would scan the current folder for vulnerabilities by default. Following arguments can be used to specify the scan path, output format and output path.
* --path for scan path (default: current directory) 
* --format for output format which can be "table" or "json"  (default: "table")
* --output_path for specifying output path
```
$ go run main.go --path=C:\Users\user\Downloads\abc-project --format=table --output_path=C:\Users\user\Downloads
```
### Ouput log
![alt text](https://github.com/shariq027/scan-deps/blob/master/docs/images/demo-shot.png)

### Support

We currently support languages and their dependency files mentioned below
* Node - package-lock.json, yarn.lock, pnpm-lock.yaml
* Java/Maven - pom.xml
* Go - go.mod, go.sum
* Python - requirements.txt

### Next Release
* Something exciting
