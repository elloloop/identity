package entdb

// asString narrows a map[string]any value to a string, defaulting to
// the empty string when the value is missing or of a wrong type. Used
// to convert service-layer field-name patches into typed proto fields
// in entRepository.UpdateXxx.
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// asBool narrows a map[string]any value to a bool, defaulting false.
func asBool(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

// asInt64 narrows a map[string]any numeric value to an int64,
// covering the int / int32 / int64 / float64 sources the service
// layer can produce when decoding RPC payloads.
func asInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case int32:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}
