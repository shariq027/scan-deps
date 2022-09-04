package parse

import (
	"os"

	"github.com/aquasecurity/go-dep-parser/pkg/golang/mod"
	"github.com/aquasecurity/go-dep-parser/pkg/golang/sum"
	"github.com/aquasecurity/go-dep-parser/pkg/java/pom"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/npm"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/pnpm"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/yarn"
	"github.com/aquasecurity/go-dep-parser/pkg/python/pip"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

type FileInfo struct {
	File *os.File
	Path string
}

type PackageParser = func(fileInfo FileInfo) ([]types.Library, string)

func FindParser(fileName string) PackageParser {
	return parsers[fileName]
}

const NpmEcosystem = "npm"
const mavenEcosystem = "Maven"
const GoEcosystem = "Go"
const PythonEcosystem = "PyPI"

var parsers = map[string]PackageParser{
	"package-lock.json": PrasePackageLock,
	"yarn.lock":         PraseYarnLock,
	"pnpm-lock.yaml":    PrasePnpmLock,
	"pom.xml":           ParsePomXml,
	"go.mod":            PraseGoMod,
	"go.sum":            PraseGoSum,
	"requirements.txt":  ParsePip,
}

func PrasePackageLock(fileInfo FileInfo) ([]types.Library, string) {
	libs, _, _ := npm.NewParser().Parse(fileInfo.File)
	return libs, NpmEcosystem
}

func PraseYarnLock(fileInfo FileInfo) ([]types.Library, string) {
	libs, _, _ := yarn.NewParser().Parse(fileInfo.File)
	return libs, NpmEcosystem
}

func PrasePnpmLock(fileInfo FileInfo) ([]types.Library, string) {
	libs, _, _ := pnpm.NewParser().Parse(fileInfo.File)
	return libs, NpmEcosystem
}

func PraseGoMod(fileInfo FileInfo) ([]types.Library, string) {
	libs, _, _ := mod.NewParser().Parse(fileInfo.File)
	return libs, GoEcosystem
}

func PraseGoSum(fileInfo FileInfo) ([]types.Library, string) {
	libs, _, _ := sum.NewParser().Parse(fileInfo.File)
	return libs, GoEcosystem
}

func ParsePomXml(fileInfo FileInfo) ([]types.Library, string) {
	libs, _, _ := pom.NewParser(fileInfo.Path).Parse(fileInfo.File)
	return libs, mavenEcosystem
}

func ParsePip(fileInfo FileInfo) ([]types.Library, string) {
	libs, _, _ := pip.NewParser().Parse(fileInfo.File)
	return libs, PythonEcosystem
}
