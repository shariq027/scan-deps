package db

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	vtypes "github.com/shariq027/scan-deps/pkg/db/types"
)

const Api = "https://api.osv.dev"

func MakeReq(libs []types.Library, ecosystem string) []vtypes.Vulnerability {
	results := make(chan *vtypes.Result)
	var res []vtypes.Vulnerability
	// Use goroutine to send multiple time-consuming jobs to the channel.
	for i := 0; i < len(libs); i++ {
		go func(num int) {
			vuln, _ := getVulns(libs[num], ecosystem)
			result := &vtypes.Result{PkgVuln: vuln, Err: nil}
			results <- result
		}(i)
	}

	for i := 0; i < len(libs); i++ {
		result := <-results
		if len(result.PkgVuln.Vulns) > 0 {
			res = append(res, result.PkgVuln)
		}
	}

	return res
}

func getVulns(lib types.Library, ecosystem string) (vtypes.Vulnerability, error) {

	var vuln vtypes.Vulnerability

	osvIp := vtypes.OsvInput{Version: lib.Version, Pkg: vtypes.Pkg{Name: lib.Name, Ecosystem: ecosystem}}

	data, err := json.Marshal(osvIp)
	if err != nil {
		log.Fatal(err)
	}

	url := "/v1/query"

	reader := bytes.NewReader(data)
	req, _ := http.NewRequest("POST", Api+url, reader)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return vuln, fmt.Errorf("%w", err)
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return vuln, fmt.Errorf(
			"(%s %s %d)",
			resp.Request.Method,
			resp.Request.URL,
			resp.StatusCode,
		)
	}

	if string(body) == "{}" {
		return vuln, nil
	} else {
		//fmt.Println(string(body))
		json.Unmarshal(body, &vuln)
		vuln.Name = lib.Name
		vuln.Version = lib.Version
		vuln.Type = ecosystem
		return vuln, nil
	}
}
