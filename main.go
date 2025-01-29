package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"text/template"
)

// HTML template for the UI
var tmpl = template.Must(template.New("index").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Email Domain Checker</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; margin: 50px; }
        input, button { padding: 10px; margin: 5px; }
        table { margin: auto; border-collapse: collapse; width: 60%; }
        th, td { border: 1px solid black; padding: 8px; }
    </style>
</head>
<body>
    <h2>Email Domain Checker</h2>
    <form action="/check" method="post">
        <input type="text" name="domain" placeholder="Enter domain (example.com)" required>
        <button type="submit">Check</button>
    </form>

    {{if .}}
    <h3>Results for: {{.Domain}}</h3>
    <table>
        <tr><th>MX</th><td>{{.HasMX}}</td></tr>
        <tr><th>SPF</th><td>{{.HasSPF}}</td></tr>
        <tr><th>SPF Record</th><td>{{.SPFRecord}}</td></tr>
        <tr><th>DMARC</th><td>{{.HasDMARC}}</td></tr>
        <tr><th>DMARC Record</th><td>{{.DMARCRecord}}</td></tr>
    </table>
    {{end}}
</body>
</html>
`))

type DomainCheck struct {
	Domain      string
	HasMX       bool
	HasSPF      bool
	SPFRecord   string
	HasDMARC    bool
	DMARCRecord string
}

// Serves the HTML form
func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl.Execute(w, nil)
}

// Handles form submission and domain lookup
func checkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	domain := r.FormValue("domain")
	if domain == "" {
		http.Error(w, "Domain is required", http.StatusBadRequest)
		return
	}

	result := checkDomain(domain)
	tmpl.Execute(w, result)
}

// Function to check domain details
func checkDomain(domain string) DomainCheck {
	var hasMX, hasSPF, hasDMARC bool
	var spfRecord, dmarcRecord string

	mxRecords, err := net.LookupMX(domain)
	if err == nil && len(mxRecords) > 0 {
		hasMX = true
	}

	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		for _, record := range txtRecords {
			if strings.HasPrefix(record, "v=spf1") {
				hasSPF = true
				spfRecord = record
				break
			}
		}
	}

	dmarcRecords, err := net.LookupTXT("_dmarc." + domain)
	if err == nil {
		for _, record := range dmarcRecords {
			if strings.HasPrefix(record, "v=DMARC1") {
				hasDMARC = true
				dmarcRecord = record
				break
			}
		}
	}

	return DomainCheck{
		Domain:      domain,
		HasMX:       hasMX,
		HasSPF:      hasSPF,
		SPFRecord:   spfRecord,
		HasDMARC:    hasDMARC,
		DMARCRecord: dmarcRecord,
	}
}

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/check", checkHandler)
	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
