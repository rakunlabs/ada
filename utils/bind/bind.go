package bind

import (
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
	typeTime       = reflect.TypeOf(time.Time{})
	typeJSONNumber = reflect.TypeOf(json.Number(""))
	typeDuration   = reflect.TypeOf(time.Duration(0))
)

// Bind binds HTTP request data to a struct based on content type and struct tags.
func Bind(req *http.Request, obj any) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	if obj == nil {
		return fmt.Errorf("binding target cannot be nil")
	}

	// Get the reflect value and type
	rv := reflect.ValueOf(obj)
	if rv.Kind() != reflect.Ptr {
		return fmt.Errorf("binding target must be a pointer")
	}

	rv = rv.Elem()
	if !rv.CanSet() {
		return fmt.Errorf("binding target must be settable")
	}

	// Parse form data first (for both form and multipart)
	if err := req.ParseForm(); err != nil {
		return fmt.Errorf("failed to parse form: %w", err)
	}

	// Parse multipart form if needed
	if strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/") {
		if err := req.ParseMultipartForm(32 << 20); err != nil { // 32MB max
			return fmt.Errorf("failed to parse multipart form: %w", err)
		}
	}

	// Bind based on content type
	contentType := req.Header.Get("Content-Type")
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
		if err := bindForm(req, rv); err != nil {
			return err
		}
	case strings.Contains(contentType, "multipart/form-data"):
		if err := bindMultipartForm(req, rv); err != nil {
			return err
		}
	}

	// Always bind query parameters, headers, and URI parameters
	if err := bindQuery(req, rv); err != nil {
		return err
	}

	if err := bindHeaders(req, rv); err != nil {
		return err
	}

	if err := bindURI(req, rv); err != nil {
		return err
	}

	return nil
}

// bindJSON binds JSON data from request body
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

// bindXML binds XML data from request body
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

// bindForm binds form data to struct fields with "form" tags
func bindForm(req *http.Request, rv reflect.Value) error {
	return bindFormData(req.Form, rv, "form")
}

// bindMultipartForm binds multipart form data to struct fields
func bindMultipartForm(req *http.Request, rv reflect.Value) error {
	if req.MultipartForm == nil {
		return nil
	}

	// Bind form values
	if err := bindFormData(req.MultipartForm.Value, rv, "form"); err != nil {
		return err
	}

	// Bind file uploads
	return bindFiles(req.MultipartForm.File, rv)
}

// bindQuery binds query parameters to struct fields with "query" tags
func bindQuery(req *http.Request, rv reflect.Value) error {
	queryParams := req.URL.Query()
	return bindFormData(queryParams, rv, "query")
}

// bindHeaders binds HTTP headers to struct fields with "header" tags
func bindHeaders(req *http.Request, rv reflect.Value) error {
	rt := rv.Type()

	for i := range rv.NumField() {
		field := rv.Field(i)
		fieldType := rt.Field(i)

		if !field.CanSet() {
			continue
		}

		headerTag := fieldType.Tag.Get("header")
		if headerTag == "" || headerTag == "-" {
			continue
		}

		headerName := headerTag
		if commaIdx := strings.Index(headerTag, ","); commaIdx != -1 {
			headerName = headerTag[:commaIdx]
		}

		headerValue := req.Header.Get(headerName)
		if headerValue == "" {
			continue
		}

		if err := setFieldValue(field, fieldType, headerValue); err != nil {
			return fmt.Errorf("failed to bind header %s: %w", headerName, err)
		}
	}

	return nil
}

// bindURI binds URI parameters to struct fields with "uri" or "param" tags
func bindURI(req *http.Request, rv reflect.Value) error {
	// This would typically be populated by the router
	// For now, we'll check if there's a context value or similar mechanism
	// This is a placeholder - actual implementation depends on your routing system

	rt := rv.Type()

	for i := range rv.NumField() {
		field := rv.Field(i)
		fieldType := rt.Field(i)

		if !field.CanSet() {
			continue
		}

		uriTag := fieldType.Tag.Get("uri")
		if uriTag == "" {
			uriTag = fieldType.Tag.Get("param")
		}

		if uriTag == "" || uriTag == "-" {
			continue
		}

		paramName := uriTag
		if commaIdx := strings.Index(uriTag, ","); commaIdx != -1 {
			paramName = uriTag[:commaIdx]
		}

		// Try to get URI parameter from request context
		if paramValue := getURIParam(req, paramName); paramValue != "" {
			if err := setFieldValue(field, fieldType, paramValue); err != nil {
				return fmt.Errorf("failed to bind URI param %s: %w", paramName, err)
			}
		}
	}

	return nil
}

// bindFormData binds form data to struct fields
func bindFormData(values url.Values, rv reflect.Value, tagName string) error {
	rt := rv.Type()

	for i := range rv.NumField() {
		field := rv.Field(i)
		fieldType := rt.Field(i)

		if !field.CanSet() {
			continue
		}

		tag := fieldType.Tag.Get(tagName)
		if tag == "" || tag == "-" {
			continue
		}

		fieldName := tag
		if commaIdx := strings.Index(tag, ","); commaIdx != -1 {
			fieldName = tag[:commaIdx]
		}

		formValues := values[fieldName]
		if len(formValues) == 0 {
			continue
		}

		// comma seperated form values
		for i, v := range formValues {
			if strings.Contains(v, ",") {
				formValues = append(formValues[:i], append(strings.Split(v, ","), formValues[i+1:]...)...)
			}
		}

		// Handle slice fields
		if field.Kind() == reflect.Slice {
			if err := setSliceField(field, fieldType, formValues); err != nil {
				return fmt.Errorf("failed to bind %s field %s: %w", tagName, fieldName, err)
			}
		} else {
			// Use the first value for non-slice fields
			if err := setFieldValue(field, fieldType, formValues[0]); err != nil {
				return fmt.Errorf("failed to bind %s field %s: %w", tagName, fieldName, err)
			}
		}
	}

	return nil
}

// bindFiles binds file uploads to struct fields
func bindFiles(files map[string][]*multipart.FileHeader, rv reflect.Value) error {
	rt := rv.Type()

	for i := range rv.NumField() {
		field := rv.Field(i)
		fieldType := rt.Field(i)

		if !field.CanSet() {
			continue
		}

		fileTag := fieldType.Tag.Get("file")
		if fileTag == "" || fileTag == "-" {
			continue
		}

		fileName := fileTag
		if commaIdx := strings.Index(fileTag, ","); commaIdx != -1 {
			fileName = fileTag[:commaIdx]
		}

		fileHeaders := files[fileName]
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

// setFieldValue sets a field value from a string
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
	case reflect.Ptr:
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}

		return setFieldValue(field.Elem(), fieldType, value)
	default:
		return fmt.Errorf("unsupported field type: %s", field.Type())
	}

	return nil
}

// setSliceField sets a slice field from multiple values
func setSliceField(field reflect.Value, fieldType reflect.StructField, values []string) error {
	slice := reflect.MakeSlice(field.Type(), len(values), len(values))

	for i, value := range values {
		elem := slice.Index(i)
		if err := setFieldValue(elem, fieldType, value); err != nil {
			return err
		}
	}

	for i := 0; i < slice.Len(); i++ {
		field.Set(reflect.Append(field, slice.Index(i)))
	}

	return nil
}

// getURIParam extracts URI parameter from request context
// This is a placeholder function - implement based on your router
func getURIParam(req *http.Request, paramName string) string {
	return req.PathValue(paramName)
}
