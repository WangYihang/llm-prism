package version

import (
	"encoding/json"
	"time"
)

var (
	Version string = "0.0.0"
	Commit  string = "unknown"
	Date    string = time.Now().Format(time.RFC3339)
)

type VersionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func GetVersionInfo() *VersionInfo {
	return &VersionInfo{
		Version: Version,
		Commit:  Commit,
		Date:    Date,
	}
}

func (v *VersionInfo) JSON() string {
	json, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(json)
}
