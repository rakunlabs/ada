package bind

import (
	"encoding"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

var (
	ErrBinding = fmt.Errorf("binding")

	typeTime        = reflect.TypeOf(time.Time{})
	typeDuration    = reflect.TypeOf(time.Duration(0))
	typeRawMessage  = reflect.TypeOf(json.RawMessage{})
	typeUnmarshaler = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()

	fieldCacheMap = make(map[reflect.Type]*fieldCache)
)

// Cached field information for faster binding.
type fieldCache struct {
	formFields   []fieldInfo
	queryFields  []fieldInfo
	headerFields []fieldInfo
	uriFields    []fieldInfo
	fileFields   []fieldInfo
}

type fieldInfo struct {
	index    int
	tagValue string
}

// getFieldCache returns cached field information for a struct type.
func getFieldCache(rt reflect.Type) *fieldCache {
	if cache, exists := fieldCacheMap[rt]; exists {
		return cache
	}

	cache := &fieldCache{
		formFields:   []fieldInfo{},
		queryFields:  []fieldInfo{},
		headerFields: []fieldInfo{},
		uriFields:    []fieldInfo{},
		fileFields:   []fieldInfo{},
	}

	for i := range rt.NumField() {
		field := rt.Field(i)

		// Form fields
		if tag := field.Tag.Get("form"); tag != "" && tag != "-" {
			if commaIdx := strings.Index(tag, ","); commaIdx != -1 {
				tag = tag[:commaIdx]
			}
			cache.formFields = append(cache.formFields, fieldInfo{index: i, tagValue: tag})
		}

		// Query fields
		if tag := field.Tag.Get("query"); tag != "" && tag != "-" {
			if commaIdx := strings.Index(tag, ","); commaIdx != -1 {
				tag = tag[:commaIdx]
			}
			cache.queryFields = append(cache.queryFields, fieldInfo{index: i, tagValue: tag})
		}

		// Header fields
		if tag := field.Tag.Get("header"); tag != "" && tag != "-" {
			if commaIdx := strings.Index(tag, ","); commaIdx != -1 {
				tag = tag[:commaIdx]
			}
			cache.headerFields = append(cache.headerFields, fieldInfo{index: i, tagValue: tag})
		}

		// URI fields
		uriTag := field.Tag.Get("uri")
		if uriTag == "" {
			uriTag = field.Tag.Get("param")
		}
		if uriTag != "" && uriTag != "-" {
			if commaIdx := strings.Index(uriTag, ","); commaIdx != -1 {
				uriTag = uriTag[:commaIdx]
			}
			cache.uriFields = append(cache.uriFields, fieldInfo{index: i, tagValue: uriTag})
		}

		// File fields
		if tag := field.Tag.Get("file"); tag != "" && tag != "-" {
			if commaIdx := strings.Index(tag, ","); commaIdx != -1 {
				tag = tag[:commaIdx]
			}
			cache.fileFields = append(cache.fileFields, fieldInfo{index: i, tagValue: tag})
		}
	}

	fieldCacheMap[rt] = cache

	return cache
}

// Bind binds HTTP request data to a struct based on content type and struct tags.
func Bind(req *http.Request, obj any, opts ...Option) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %s", ErrBinding, err)
		}
	}()

	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if obj == nil {
		return fmt.Errorf("binding target cannot be nil")
	}

	// Get the reflect value and type
	rv := reflect.ValueOf(obj)
	if rv.Kind() != reflect.Pointer {
		return fmt.Errorf("binding target must be a pointer")
	}

	rv = rv.Elem()
	if !rv.CanSet() {
		return fmt.Errorf("binding target must be settable")
	}

	rt := rv.Type()
	cache := getFieldCache(rt)

	opt := applyOptions(opts...)

	// Bind based on content type
	contentType := req.Header.Get("Content-Type")

	// Parse form data if it's a form type
	if strings.Contains(contentType, "application/x-www-form-urlencoded") || strings.Contains(contentType, "multipart/form-data") {
		if err := req.ParseForm(); err != nil {
			return fmt.Errorf("failed to parse form: %w", err)
		}

		if strings.HasPrefix(contentType, "multipart/") {
			if err := req.ParseMultipartForm(opt.MultipartFormMaxMemory); err != nil {
				return fmt.Errorf("failed to parse multipart form: %w", err)
			}
		}
	}

	switch {
	case strings.Contains(contentType, "application/json"):
		if err := bindJSON(req, rv); err != nil {
			return err
		}
	case strings.Contains(contentType, "application/xml"), strings.Contains(contentType, "text/xml"):
		if err := bindXML(req, rv); err != nil {
			return err
		}
	case strings.Contains(contentType, "application/x-www-form-urlencoded"):
		if err := bindForm(req, rv, cache); err != nil {
			return err
		}
	case strings.Contains(contentType, "multipart/form-data"):
		if err := bindMultipartForm(req, rv, cache); err != nil {
			return err
		}
	}

	// Always bind query parameters, headers, and URI parameters
	if err := bindQuery(req, rv, opt.QuerySeparator, cache); err != nil {
		return err
	}

	if err := bindHeaders(req, rv, cache); err != nil {
		return err
	}

	if err := bindURI(req, rv, cache); err != nil {
		return err
	}

	return nil
}

// bindJSON binds JSON data from request body.
func bindJSON(req *http.Request, rv reflect.Value) error {
	if req.Body == nil {
		return nil
	}

	decoder := json.NewDecoder(req.Body)
	decoder.UseNumber()

	if err := decoder.Decode(rv.Addr().Interface()); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}

	return nil
}

// bindXML binds XML data from request body.
func bindXML(req *http.Request, rv reflect.Value) error {
	if req.Body == nil {
		return nil
	}

	decoder := xml.NewDecoder(req.Body)

	if err := decoder.Decode(rv.Addr().Interface()); err != nil {
		return fmt.Errorf("failed to decode XML: %w", err)
	}

	return nil
}

// bindForm binds form data to struct fields with "form" tags.
func bindForm(req *http.Request, rv reflect.Value, cache *fieldCache) error {
	return bindFormData(req.Form, rv, cache.formFields, "")
}

// bindMultipartForm binds multipart form data to struct fields.
func bindMultipartForm(req *http.Request, rv reflect.Value, cache *fieldCache) error {
	if req.MultipartForm == nil {
		return nil
	}

	// Bind form values
	if err := bindFormData(req.MultipartForm.Value, rv, cache.formFields, ""); err != nil {
		return err
	}

	// Bind file uploads
	return bindFiles(req.MultipartForm.File, rv, cache)
}

// bindQuery binds query parameters to struct fields with "query" tags.
func bindQuery(req *http.Request, rv reflect.Value, sep string, cache *fieldCache) error {
	return bindFormData(req.URL.Query(), rv, cache.queryFields, sep)
}

// bindHeaders binds HTTP headers to struct fields with "header" tags.
func bindHeaders(req *http.Request, rv reflect.Value, cache *fieldCache) error {
	for _, fieldInfo := range cache.headerFields {
		field := rv.Field(fieldInfo.index)
		fieldType := rv.Type().Field(fieldInfo.index)

		if !field.CanSet() {
			continue
		}

		headerValue := req.Header.Get(fieldInfo.tagValue)
		if headerValue == "" {
			continue
		}

		if err := setFieldValue(field, fieldType, headerValue); err != nil {
			return fmt.Errorf("failed to bind header %s: %w", fieldInfo.tagValue, err)
		}
	}

	return nil
}

// bindURI binds URI parameters to struct fields with "uri" or "param" tags.
func bindURI(req *http.Request, rv reflect.Value, cache *fieldCache) error {
	// This would typically be populated by the router
	// For now, we'll check if there's a context value or similar mechanism
	// This is a placeholder - actual implementation depends on your routing system

	for _, fieldInfo := range cache.uriFields {
		field := rv.Field(fieldInfo.index)
		fieldType := rv.Type().Field(fieldInfo.index)

		if !field.CanSet() {
			continue
		}

		// Try to get URI parameter from request context
		if paramValue := req.PathValue(fieldInfo.tagValue); paramValue != "" {
			if err := setFieldValue(field, fieldType, paramValue); err != nil {
				return fmt.Errorf("failed to bind URI param %s: %w", fieldInfo.tagValue, err)
			}
		}
	}

	return nil
}

// bindFormData binds form data to struct fields.
func bindFormData(values url.Values, rv reflect.Value, fields []fieldInfo, sep string) error {
	for _, fieldInfo := range fields {
		field := rv.Field(fieldInfo.index)
		fieldType := rv.Type().Field(fieldInfo.index)

		if !field.CanSet() {
			continue
		}

		formValues := values[fieldInfo.tagValue]
		if len(formValues) == 0 {
			continue
		}

		// comma separated values
		if sep != "" {
			for i, v := range formValues {
				if strings.Contains(v, sep) {
					formValues = append(formValues[:i], append(strings.Split(v, sep), formValues[i+1:]...)...)
				}
			}
		}

		// Handle json.RawMessage specially (it's a []byte but should be treated as a single value)
		if field.Type() == typeRawMessage {
			field.Set(reflect.ValueOf(json.RawMessage(formValues[0])))
			continue
		}

		// Handle slice of json.RawMessage
		if field.Kind() == reflect.Slice && field.Type().Elem() == typeRawMessage {
			slice := reflect.MakeSlice(field.Type(), len(formValues), len(formValues))
			for i, v := range formValues {
				slice.Index(i).Set(reflect.ValueOf(json.RawMessage(v)))
			}
			field.Set(slice)
			continue
		}

		// Handle struct/map/pointer-to-struct fields by attempting JSON unmarshal
		if shouldJSONUnmarshal(field) {
			if err := json.Unmarshal([]byte(formValues[0]), field.Addr().Interface()); err != nil {
				return fmt.Errorf("failed to unmarshal JSON for field %s: %w", fieldInfo.tagValue, err)
			}
			continue
		}

		// Handle slice of structs/maps by attempting JSON unmarshal on each element
		if field.Kind() == reflect.Slice && shouldJSONUnmarshalElem(field.Type().Elem()) {
			slice := reflect.MakeSlice(field.Type(), len(formValues), len(formValues))
			for i, v := range formValues {
				elem := slice.Index(i)
				if elem.Kind() == reflect.Pointer {
					elem.Set(reflect.New(elem.Type().Elem()))
				}
				target := elem.Addr().Interface()
				if elem.Kind() == reflect.Pointer {
					target = elem.Interface()
				}
				if err := json.Unmarshal([]byte(v), target); err != nil {
					return fmt.Errorf("failed to unmarshal JSON for field %s[%d]: %w", fieldInfo.tagValue, i, err)
				}
			}
			field.Set(slice)
			continue
		}

		// Handle slice fields
		if field.Kind() == reflect.Slice {
			if err := setSliceField(field, fieldType, formValues); err != nil {
				return fmt.Errorf("failed to bind field %s: %w", fieldInfo.tagValue, err)
			}
		} else {
			// Use the first value for non-slice fields
			if err := setFieldValue(field, fieldType, formValues[0]); err != nil {
				return fmt.Errorf("failed to bind field %s: %w", fieldInfo.tagValue, err)
			}
		}
	}

	return nil
}

// bindFiles binds file uploads to struct fields.
func bindFiles(files map[string][]*multipart.FileHeader, rv reflect.Value, cache *fieldCache) error {
	for _, fieldInfo := range cache.fileFields {
		field := rv.Field(fieldInfo.index)

		if !field.CanSet() {
			continue
		}

		fileHeaders := files[fieldInfo.tagValue]
		if len(fileHeaders) == 0 {
			continue
		}

		// Handle different field types for files
		if field.Kind() == reflect.Slice {
			// Multiple files
			elemType := field.Type().Elem()
			if elemType == reflect.TypeOf((*multipart.FileHeader)(nil)) {
				slice := reflect.MakeSlice(field.Type(), len(fileHeaders), len(fileHeaders))
				for j, fh := range fileHeaders {
					slice.Index(j).Set(reflect.ValueOf(fh))
				}
				field.Set(slice)
			}
		} else if field.Type() == reflect.TypeOf((*multipart.FileHeader)(nil)) {
			// Single file
			field.Set(reflect.ValueOf(fileHeaders[0]))
		}
	}

	return nil
}

// setFieldValue sets a field value from a string.
func setFieldValue(field reflect.Value, fieldType reflect.StructField, value string) error {
	// Handle special types first before checking Kind()
	if field.Type() == typeDuration {
		durationVal, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("failed to parse duration %s: %s %w", field.Type(), value, err)
		}

		field.Set(reflect.ValueOf(durationVal))

		return nil
	}

	if field.Type() == typeTime {
		timeFormat := fieldType.Tag.Get("time_format")
		if timeFormat == "" {
			timeFormat = time.RFC3339Nano // Default format
		}

		timeVal, err := time.Parse(timeFormat, value)
		if err != nil {
			return err
		}

		field.Set(reflect.ValueOf(timeVal))

		return nil
	}

	// Handle json.RawMessage type
	if field.Type() == typeRawMessage {
		field.Set(reflect.ValueOf(json.RawMessage(value)))

		return nil
	}

	switch field.Kind() {
	case reflect.String:
		field.SetString(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if intVal, err := strconv.ParseInt(value, 10, 64); err != nil {
			return err
		} else {
			field.SetInt(intVal)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if uintVal, err := strconv.ParseUint(value, 10, 64); err != nil {
			return err
		} else {
			field.SetUint(uintVal)
		}
	case reflect.Float32, reflect.Float64:
		if floatVal, err := strconv.ParseFloat(value, field.Type().Bits()); err != nil {
			return err
		} else {
			field.SetFloat(floatVal)
		}
	case reflect.Bool:
		if boolVal, err := strconv.ParseBool(value); err != nil {
			return err
		} else {
			field.SetBool(boolVal)
		}
	case reflect.Pointer:
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}

		return setFieldValue(field.Elem(), fieldType, value)
	default:
		// Handle types that implement encoding.TextUnmarshaler
		if field.Type().Implements(typeUnmarshaler) || reflect.PointerTo(field.Type()).Implements(typeUnmarshaler) {
			unmarshaler, _ := field.Addr().Interface().(encoding.TextUnmarshaler)
			if unmarshaler != nil {
				if err := unmarshaler.UnmarshalText([]byte(value)); err != nil {
					return fmt.Errorf("failed to unmarshal text for field %s: %w", fieldType.Name, err)
				}
			}

			return nil
		}

		return fmt.Errorf("unsupported field type: %s", field.Type())
	}

	return nil
}

// setSliceField sets a slice field from multiple values.
func setSliceField(field reflect.Value, fieldType reflect.StructField, values []string) error {
	slice := reflect.MakeSlice(field.Type(), len(values), len(values))

	for i, value := range values {
		elem := slice.Index(i)
		if err := setFieldValue(elem, fieldType, value); err != nil {
			return err
		}
	}

	for i := range slice.Len() {
		field.Set(reflect.Append(field, slice.Index(i)))
	}

	return nil
}

// shouldJSONUnmarshal returns true if the field should be JSON unmarshaled.
// This applies to struct, map, and pointer-to-struct/map types.
func shouldJSONUnmarshal(field reflect.Value) bool {
	// Check if type implements TextUnmarshaler - those should use text unmarshaling instead
	if field.Type().Implements(typeUnmarshaler) || reflect.PointerTo(field.Type()).Implements(typeUnmarshaler) {
		return false
	}

	kind := field.Kind()

	if kind == reflect.Struct {
		// Exclude special types that are handled elsewhere
		if field.Type() == typeTime {
			return false
		}
		return true
	}

	if kind == reflect.Map {
		return true
	}

	if kind == reflect.Pointer {
		elemType := field.Type().Elem()
		// Check if pointed type implements TextUnmarshaler
		if elemType.Implements(typeUnmarshaler) || reflect.PointerTo(elemType).Implements(typeUnmarshaler) {
			return false
		}

		elemKind := elemType.Kind()
		if elemKind == reflect.Struct {
			if elemType == typeTime {
				return false
			}
			return true
		}
		if elemKind == reflect.Map {
			return true
		}
	}

	return false
}

// shouldJSONUnmarshalElem returns true if the slice element type should be JSON unmarshaled.
func shouldJSONUnmarshalElem(elemType reflect.Type) bool {
	// Check if type implements TextUnmarshaler - those should use text unmarshaling instead
	if elemType.Implements(typeUnmarshaler) || reflect.PointerTo(elemType).Implements(typeUnmarshaler) {
		return false
	}

	kind := elemType.Kind()

	if kind == reflect.Struct {
		if elemType == typeTime {
			return false
		}
		return true
	}

	if kind == reflect.Map {
		return true
	}

	if kind == reflect.Pointer {
		pointedType := elemType.Elem()
		// Check if pointed type implements TextUnmarshaler
		if pointedType.Implements(typeUnmarshaler) || reflect.PointerTo(pointedType).Implements(typeUnmarshaler) {
			return false
		}

		pointedKind := pointedType.Kind()
		if pointedKind == reflect.Struct {
			if pointedType == typeTime {
				return false
			}
			return true
		}
		if pointedKind == reflect.Map {
			return true
		}
	}

	return false
}
