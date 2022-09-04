package display

import (
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/table"
	vtypes "github.com/shariq027/scan-deps/pkg/db/types"
)

type TabData struct {
	Type          string
	Name          string
	Version       string
	Cve           []string
	Serverity     []string
	FixedVersions []string
}

func PrintTable(vulns []vtypes.Vulnerability) {

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Type", "Name", "version", "Vulnerability", "Serverity", "Fixed Version"})

	tableData := processData(vulns)

	for _, row := range tableData {
		t.AppendRow(table.Row{row.Type, row.Name, row.Version, strings.Join(row.Cve, "\n"), strings.Join(row.Serverity, "\n"), strings.Join(row.FixedVersions, ", ")})
	}

	t.Render()
}

func processData(allVulns []vtypes.Vulnerability) []TabData {
	var tabData []TabData

	for _, pkg := range allVulns {
		var cveIds []string
		var fixedVersions []string
		var severity []string
		for _, vuln := range pkg.Vulns {
			cveIds = append(cveIds, vuln.Aliases...)
			if vuln.DatabaseSpecific.Severity != "" {
				severity = append(severity, vuln.DatabaseSpecific.Severity)
			}
			fixedVersions = append(fixedVersions, getFixedVersions(vuln.Affected)...)
		}
		tabData = append(tabData, TabData{Type: pkg.Type, Name: pkg.Name, Version: pkg.Version, Cve: cveIds, Serverity: severity, FixedVersions: unique(fixedVersions)})
	}

	return tabData
}

func getFixedVersions(affectedVers []vtypes.Affected) []string {
	var versions []string

	for _, affVersion := range affectedVers {
		for _, vrange := range affVersion.Ranges {
			for _, event := range vrange.Events {
				if event.Fixed != "" {
					versions = append(versions, event.Fixed)
				}
			}

		}

	}

	return versions
}

func unique(arr []string) []string {
	occurred := map[string]bool{}
	result := []string{}
	for e := range arr {

		if !occurred[arr[e]] {
			occurred[arr[e]] = true

			result = append(result, arr[e])
		}
	}

	return result
}
