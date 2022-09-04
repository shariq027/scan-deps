package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/shariq027/scan-deps/pkg/db"
	vtypes "github.com/shariq027/scan-deps/pkg/db/types"
	"github.com/shariq027/scan-deps/pkg/display"
	"github.com/shariq027/scan-deps/pkg/parse"
)

const TabFormat = "table"
const JsonFormat = "json"
const colorGreen = "\033[32m"
const colorReset = "\033[0m"

func run(path string) []vtypes.Vulnerability {
	var scannedVulns []vtypes.Vulnerability
	dependecyFilesExists := false

	fmt.Println(string(colorGreen), "Searching for dependency files to scan..", string(colorReset))
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {

		if err != nil {

			fmt.Println(err)
			return nil
		}

		if !info.IsDir() {
			parser := parse.FindParser(info.Name())
			if parser == nil {
				return nil
			}
			dependecyFilesExists = true
			f, err := os.Open(path)
			if err != nil {
				panic(err)
			}
			defer f.Close()

			libs, ecosystem := parser(parse.FileInfo{File: f, Path: path})
			vulnList := db.MakeReq(libs, ecosystem)
			scannedVulns = append(scannedVulns, vulnList...)
		}

		return nil
	})

	if err != nil {
		fmt.Println(err)
	}
	if !dependecyFilesExists {
		fmt.Println("No dependency files found")
	}

	return scannedVulns
}

func main() {

	var path = flag.String("path", ".", "Path to scan vulnerabilities")
	var format = flag.String("format", "table", "Output format")
	var output_path = flag.String("output_path", "", "Path to store Output JSON")

	flag.Parse()

	scannedVulns := run(*path)

	if *format == TabFormat {
		display.PrintTable(scannedVulns)
	} else if *format == JsonFormat {
		b, err := json.Marshal(scannedVulns)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(string(b))
	}

	if *output_path != "" {
		file, _ := json.MarshalIndent(scannedVulns, "", " ")
		err := ioutil.WriteFile(*output_path+"/results.json", file, 0644)
		if err != nil {
			fmt.Println(err)
		}
	}
}
