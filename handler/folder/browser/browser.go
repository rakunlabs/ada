package browser

import (
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strconv"

	"github.com/rakunlabs/ada/handler/folder"
	_ "github.com/rytsh/mugo/fstore/registry/codec"
	_ "github.com/rytsh/mugo/fstore/registry/minify"

	"github.com/rytsh/mugo/render"
)

func init() {
	folder.BrowserFunc = Browser
}

func Browser(w http.ResponseWriter, r *http.Request, opt folder.BrowserOption) error {
	dirs, err := opt.Folder.Readdir(-1)
	if err != nil {
		return fmt.Errorf("Error reading directory")
	}
	folderDirs := []fs.FileInfo{}
	folderFiles := []fs.FileInfo{}
	for _, dir := range dirs {
		if dir.IsDir() {
			folderDirs = append(folderDirs, dir)
		} else {
			folderFiles = append(folderFiles, dir)
		}
	}

	query := r.URL.Query()
	sortField := query.Get("sort")
	sortDesc, _ := strconv.ParseBool(query.Get("desc"))

	sort.Slice(folderDirs, sortTable(sortField, sortDesc, folderDirs))
	sort.Slice(folderFiles, sortTable(sortField, sortDesc, folderFiles))

	dirs = append(folderDirs, folderFiles...)

	values := map[string]interface{}{
		"basePath":  opt.BasePath,
		"dirs":      dirs,
		"url":       r.URL.Path,
		"utc":       opt.UTC,
		"sortField": sortField,
		"sortDesc":  sortDesc,
	}

	v, err := render.ExecuteWithData(`
{{- define "style" -}}
body {
	padding: 0;
	margin: 0;
}

table tr:nth-child(even) {
	background-color: #e5e5e5;
}
table tr:hover > td {
	background-color:#ff4000;
	color: #fff;
}
table tr:hover a, th a {
	color: inherit;
	text-decoration: none;
}
{{- end -}}
{{- define "html" -}}
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=640, initial-scale=1.0">
	<title>Browser</title>
	<style>{{ execTemplate "style" "" | codec.StringToByte | minify "css" | codec.ByteToString }}</style>
</head>
<body>
<table>
	<colgroup>
		<col span="1" style="width: 50%;">
		<col span="1" style="width: 25%;">
		<col span="1" style="width: 25%;">
	</colgroup>
	<tr style="background-color: #000; color: #fff;">
		<th><a href="./?sort=title{{and (eq .sortField "title") (not .sortDesc) | ternary "&desc=1" "" }}">Title</a></th>
		<th><a href="./?sort=size{{and (eq .sortField "size") (not .sortDesc) | ternary "&desc=1" "" }}">File Size</a></th>
		<th><a href="./?sort=date{{and (eq .sortField "date") (not .sortDesc) | ternary "&desc=1" "" }}">Last Modified</a></th>
	</tr>
	{{- if ne .url .basePath }}
	<tr>
		<td>📁 <a href="../">..</a></td>
		<td>-</td>
		<td>-</td>
	</tr>
	{{- end }}
	{{- range .dirs }}
	<tr>
		<td>{{ ternary "📁" "📄" .IsDir }} <a href="./{{ .Name }}{{ ternary "/" "" .IsDir }}" {{ ternary "" "download" .IsDir }}>{{ html2.EscapeString .Name }}{{ ternary "/" "" .IsDir }}</a></td>
		<td>{{ .Size | cast.ToUint64 | humanize.Bytes }}</td>
		<td>{{ time.Format time.RFC3339 (ternary (time.UTC .ModTime) .ModTime $.utc) }}</td>
	</tr>
	{{- end }}
</body>
</html>
{{- end -}}
{{ execTemplate "html" . | codec.StringToByte | minify "html" | codec.ByteToString }}
`, values)
	if err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}

	if opt.BrowseCache != "" {
		w.Header().Set("Cache-Control", opt.BrowseCache)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(v)

	return err
}

func sortTable(sortField string, sortDesc bool, fs []fs.FileInfo) func(i, j int) bool {
	return func(i, j int) bool {
		ret := false
		switch sortField {
		case "name":
			ret = fs[i].Name() < fs[j].Name()
		case "size":
			ret = fs[i].Size() < fs[j].Size()
		case "date":
			ret = fs[i].ModTime().Before(fs[j].ModTime())
		default:
			ret = fs[i].Name() < fs[j].Name()
		}

		if sortDesc {
			return !ret
		}

		return ret
	}
}
