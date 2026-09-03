package ai

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// UnmarshalJSON makes Analysis strict even when callers decode it outside the
// gateway client. Go's default decoder is case-insensitive and accepts
// duplicate object keys, neither of which is acceptable at this trust boundary.
func (analysis *Analysis) UnmarshalJSON(data []byte) error {
	if analysis == nil {
		return errors.New("nil analysis target")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return errors.New("analysis JSON contains duplicate or invalid keys")
	}
	if err := validateExactAnalysisShape(data); err != nil {
		return err
	}
	type plainAnalysis Analysis
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded plainAnalysis
	if err := decoder.Decode(&decoded); err != nil {
		return errors.New("analysis JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("analysis JSON contains trailing data")
	}
	*analysis = Analysis(decoded)
	return nil
}

func validateExactAnalysisShape(data []byte) error {
	top, err := decodeRawObject(data)
	if err != nil || !hasExactKeys(top, "schemaVersion", "summary", "rankedFindings", "humanVerificationSteps", "recommendations", "executionAllowed") {
		return errors.New("analysis JSON has an invalid top-level shape")
	}
	collections := []struct {
		name string
		keys []string
	}{
		{name: "rankedFindings", keys: []string{"findingId", "rank", "rationale"}},
		{name: "humanVerificationSteps", keys: []string{"findingId", "description"}},
		{name: "recommendations", keys: []string{"findingId", "priority", "advice"}},
	}
	for _, collection := range collections {
		var items []json.RawMessage
		if err := json.Unmarshal(top[collection.name], &items); err != nil {
			return errors.New("analysis JSON collection shape is invalid")
		}
		for _, item := range items {
			object, err := decodeRawObject(item)
			if err != nil || !hasExactKeys(object, collection.keys...) {
				return errors.New("analysis JSON item shape is invalid")
			}
		}
	}
	return nil
}

func decodeRawObject(data []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, errors.New("JSON value is not an object")
	}
	return object, nil
}

func hasExactKeys(object map[string]json.RawMessage, keys ...string) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, exists := object[key]; !exists {
			return false
		}
	}
	return true
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := inspectJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is invalid")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("JSON object key is duplicated")
			}
			seen[key] = struct{}{}
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
