package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const apiURL = "https://959ace9c3696e782907cc55f745072.82.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/869cde8a8c084ddb8f871a560caee5a2/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=_PCOBWWmhGSx8881tc57qpawRkQuNHCWWj0TXtHwa3k"
const defaultPageLimit = 50
const maxPageLimit = 500

var apiClient = &http.Client{Timeout: 45 * time.Second}

type CVE struct {
	CVEID         string  `json:"cve_id"`
	CWEID         string  `json:"cwe_id"`
	CVSSScore     float64 `json:"cvss_score"`
	Severity      string  `json:"severity"`
	PublishedDate string  `json:"published_date"`
	Description   string  `json:"description"`
	SourceLink    string  `json:"source_link"`
}

type APIResponse struct {
	Value    []map[string]interface{} `json:"value"`
	NextPage int                      `json:"nextPage"`
	HasMore  bool                     `json:"hasMore"`
}

type PowerAutomateRequest struct {
	FilterString string `json:"filterString"`
	FetchXML     string `json:"fetchXml"`
	Limit        int    `json:"limit"`
	Page         int    `json:"page"`
}

type CVEPage struct {
	Value    []CVE `json:"value"`
	NextPage int   `json:"nextPage,omitempty"`
	HasMore  bool  `json:"hasMore"`
}

func fetchCVEs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	limit := parseLimit(r.URL.Query().Get("limit"))
	pageNumber := parsePage(r.URL.Query().Get("page"))
	filterString := strings.TrimSpace(r.URL.Query().Get("filterString"))
	if filterString == "" {
		filterString = buildFilterString(r.URL.Query().Get("q"), r.URL.Query().Get("severity"))
	}
	fetchXML := buildFetchXML(limit, pageNumber, filterString)

	payload, err := json.Marshal(PowerAutomateRequest{
		FilterString: filterString,
		FetchXML:     fetchXML,
		Limit:        limit,
		Page:         pageNumber,
	})
	if err != nil {
		log.Printf("Error encoding request: %v", err)
		http.Error(w, `{"error":"Failed to encode request"}`, http.StatusInternalServerError)
		return
	}

	// POST pagination inputs to the Power Automate HTTP trigger.
	resp, err := apiClient.Post(apiURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("Error fetching API: %v", err)
		http.Error(w, `{"error":"Failed to fetch CVE data"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response: %v", err)
		http.Error(w, `{"error":"Failed to read response"}`, http.StatusInternalServerError)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Power Automate returned %d: %s", resp.StatusCode, string(body[:min(500, len(body))]))
		http.Error(w, `{"error":"Power Automate returned an error"}`, http.StatusBadGateway)
		return
	}

	// Find the first complete JSON object (in case of multiple responses)
	bodyStr := firstJSONObject(string(body))

	// Parse API response
	var apiResp APIResponse
	if err := json.Unmarshal([]byte(bodyStr), &apiResp); err != nil {
		log.Printf("Error parsing JSON: %v, body preview: %s", err, bodyStr[:min(500, len(bodyStr))])
		http.Error(w, `{"error":"Failed to parse JSON"}`, http.StatusInternalServerError)
		return
	}

	// Transform to clean CVE objects
	cves := make([]CVE, 0, len(apiResp.Value))
	for _, item := range apiResp.Value {
		cve := CVE{
			CVEID:       getString(item, "cr224_cve_id"),
			CWEID:       getString(item, "cr224_cwe_id"),
			Severity:    getString(item, "cr224_severity"),
			Description: getString(item, "cr224_description"),
			SourceLink:  getString(item, "cr224_source_link"),
		}
		if score, ok := item["cr224_cvss_score"].(float64); ok {
			cve.CVSSScore = score
		}
		if date, ok := item["cr224_published_date"].(string); ok {
			cve.PublishedDate = date
		}
		cves = append(cves, cve)
	}

	page := CVEPage{
		Value:    cves,
		NextPage: apiResp.NextPage,
		HasMore:  apiResp.HasMore,
	}

	log.Printf("Successfully fetched %d CVEs (page=%d, nextPage=%d, hasMore=%t)", len(cves), pageNumber, page.NextPage, page.HasMore)
	json.NewEncoder(w).Encode(page)
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func parseLimit(raw string) int {
	if raw == "" {
		return defaultPageLimit
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return defaultPageLimit
	}
	if limit > maxPageLimit {
		return maxPageLimit
	}
	return limit
}

func parsePage(raw string) int {
	page, err := strconv.Atoi(raw)
	if err != nil || page <= 0 {
		return 1
	}
	return page
}

func buildFilterString(rawQuery string, rawSeverity string) string {
	var builder strings.Builder
	builder.WriteString(`<filter type="and">`)
	builder.WriteString(`<condition attribute="cr224_cve_id" operator="not-null" />`)

	query := strings.TrimSpace(rawQuery)
	if query != "" {
		escapedQuery := escapeXMLAttribute("%" + query + "%")
		builder.WriteString(`<filter type="or">`)
		builder.WriteString(`<condition attribute="cr224_cve_id" operator="like" value="` + escapedQuery + `" />`)
		builder.WriteString(`<condition attribute="cr224_cwe_id" operator="like" value="` + escapedQuery + `" />`)
		builder.WriteString(`<condition attribute="cr224_description" operator="like" value="` + escapedQuery + `" />`)
		builder.WriteString(`</filter>`)
	}

	severity := strings.ToUpper(strings.TrimSpace(rawSeverity))
	if severity != "" && severity != "ALL" {
		builder.WriteString(`<condition attribute="cr224_severity" operator="eq" value="` + escapeXMLAttribute(severity) + `" />`)
	}

	builder.WriteString(`</filter>`)
	return builder.String()
}

func escapeXMLAttribute(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(s)
}

func buildFetchXML(limit int, page int, filterString string) string {
	return `<fetch count="` + strconv.Itoa(limit) + `" page="` + strconv.Itoa(page) + `">
  <entity name="cr224_cve_feed">
    <attribute name="cr224_cve_id" />
    <attribute name="cr224_cwe_id" />
    <attribute name="cr224_cvss_score" />
    <attribute name="cr224_severity" />
    <attribute name="cr224_published_date" />
    <attribute name="cr224_description" />
    <attribute name="cr224_source_link" />
    <order attribute="cr224_published_date" descending="true" />
    ` + filterString + `
  </entity>
</fetch>`
}

func firstJSONObject(bodyStr string) string {
	depth := 0
	endIdx := -1
	for i, c := range bodyStr {
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				endIdx = i + 1
				break
			}
		}
	}
	if endIdx > 0 {
		return bodyStr[:endIdx]
	}
	return bodyStr
}

func main() {
	// Serve static files
	http.Handle("/", http.FileServer(http.Dir(".")))

	// API endpoint
	http.HandleFunc("/api/cves", fetchCVEs)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server running at http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
