package registry

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"unicode/utf8"
)

const maxSQLiteRecordBytes = 64 * 1024

// decodeSQLiteRecord accepts only the exact internal record representation.
// Struct fields are mandatory; NULL is allowed only for typed pointer/slice
// fields. Unknown/duplicate/case-folded fields, maps, trailing data, invalid UTF-8
// and ambiguous unsigned numeric forms are rejected before unmarshalling.
func decodeSQLiteRecord(data string, output any) error {
	if len(data) == 0 || len(data) > maxSQLiteRecordBytes || !utf8.ValidString(data) {
		return invalid("sqlite.record_json")
	}
	value := reflect.ValueOf(output)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() ||
		value.Elem().Kind() != reflect.Struct {
		return invalid("sqlite.record_target")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(data))
	decoder.UseNumber()
	if err := sqliteRecordValue(decoder, value.Elem().Type()); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return invalid("sqlite.record_trailing")
	}
	if err := json.Unmarshal([]byte(data), output); err != nil {
		return invalid("sqlite.record_json")
	}
	return nil
}

func sqliteRecordValue(decoder *json.Decoder, target reflect.Type) error {
	token, err := decoder.Token()
	if err != nil {
		return invalid("sqlite.record_json")
	}
	return sqliteRecordToken(decoder, target, token)
}

func sqliteRecordToken(decoder *json.Decoder, target reflect.Type, token any) error {
	if token == nil {
		if target.Kind() == reflect.Pointer || target.Kind() == reflect.Slice {
			return nil
		}
		return invalid("sqlite.record_null")
	}
	if target.Kind() == reflect.Pointer {
		return sqliteRecordToken(decoder, target.Elem(), token)
	}
	switch target.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return invalid("sqlite.record_object")
		}
		fields := make(map[string]reflect.Type, target.NumField())
		for index := 0; index < target.NumField(); index++ {
			field := target.Field(index)
			if field.PkgPath != "" {
				return invalid("sqlite.record_target")
			}
			fields[field.Name] = field.Type
		}
		seen := make(map[string]bool, len(fields))
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return invalid("sqlite.record_field")
			}
			name, ok := key.(string)
			field, exists := fields[name]
			if !ok || !exists || seen[name] {
				return invalid("sqlite.record_field")
			}
			seen[name] = true
			if err := sqliteRecordValue(decoder, field); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') || len(seen) != len(fields) {
			return invalid("sqlite.record_fields")
		}
	case reflect.String:
		if _, ok := token.(string); !ok {
			return invalid("sqlite.record_string")
		}
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return invalid("sqlite.record_boolean")
		}
	case reflect.Uint32, reflect.Uint64:
		number, ok := token.(json.Number)
		if !ok {
			return invalid("sqlite.record_number")
		}
		digits := number.String()
		if digits == "" {
			return invalid("sqlite.record_number")
		}
		for index := range digits {
			if digits[index] < '0' || digits[index] > '9' {
				return invalid("sqlite.record_number")
			}
		}
		if _, err := strconv.ParseUint(digits, 10, target.Bits()); err != nil {
			return invalid("sqlite.record_number")
		}
	case reflect.Slice:
		if token != json.Delim('[') {
			return invalid("sqlite.record_array")
		}
		for decoder.More() {
			if err := sqliteRecordValue(decoder, target.Elem()); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return invalid("sqlite.record_array")
		}
	default:
		return invalid("sqlite.record_target")
	}
	return nil
}
