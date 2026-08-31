package audit

import (
	"fmt"
	"reflect"
	"strings"
)

var sensitiveFragments = []string{
	"secret", "token", "password", "passphrase", "privatekey", "private_key",
	"authorization", "cookie", "ciphertext", "wrappedkey", "wrapped_key",
}

// SanitizeDetails recursively removes values whose keys may contain secrets.
// Audit callers should still prefer small allow-listed detail maps.
func SanitizeDetails(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		if sensitiveKey(key) {
			output[key] = "[redacted]"
			continue
		}
		output[key] = sanitizeValue(value, 0)
	}
	return output
}

func sanitizeValue(value any, depth int) any {
	if value == nil {
		return nil
	}
	if depth > 12 {
		return "[maximum depth]"
	}
	if binary, ok := value.([]byte); ok {
		return fmt.Sprintf("[binary:%d bytes]", len(binary))
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return "[unsupported map]"
		}
		output := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			key := iterator.Key().String()
			if sensitiveKey(key) {
				output[key] = "[redacted]"
			} else {
				output[key] = sanitizeValue(iterator.Value().Interface(), depth+1)
			}
		}
		return output
	case reflect.Slice, reflect.Array:
		output := make([]any, reflected.Len())
		for i := 0; i < reflected.Len(); i++ {
			output[i] = sanitizeValue(reflected.Index(i).Interface(), depth+1)
		}
		return output
	case reflect.Pointer:
		if reflected.IsNil() {
			return nil
		}
		return sanitizeValue(reflected.Elem().Interface(), depth+1)
	default:
		return value
	}
}

func sensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", ""))
	for _, fragment := range sensitiveFragments {
		fragment = strings.ReplaceAll(fragment, "_", "")
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}
