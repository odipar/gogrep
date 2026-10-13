package sarif

import (
	"bytes"
	"encoding/json"
)

// toolName replaces opengrep's tool.driver.name, so that GitHub code
// scanning lists the results under gogrep.
const toolName = "gogrep"

// Rebrand sets tool.driver.name to "gogrep" in every run of the SARIF log
// data, leaving all other fields untouched. The log is encoded again, with
// sorted keys and with <, > and & escaped; numbers keep their text. It is an
// error when data does not start with a JSON object.
func Rebrand(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var log map[string]any
	if err := dec.Decode(&log); err != nil {
		return nil, err
	}
	runs, _ := log["runs"].([]any)
	for _, r := range runs {
		run, _ := r.(map[string]any)
		tool, _ := run["tool"].(map[string]any)
		if driver, ok := tool["driver"].(map[string]any); ok {
			driver["name"] = toolName
		}
	}
	return json.Marshal(log)
}
