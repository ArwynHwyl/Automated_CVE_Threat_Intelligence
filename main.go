package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

const apiURL = "https://959ace9c3696e782907cc55f745072.82.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/869cde8a8c084ddb8f871a560caee5a2/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=_PCOBWWmhGSx8881tc57qpawRkQuNHCWWj0TXtHwa3k"

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
	Value []map[string]interface{} `json:"value"`
}

func fetchCVEs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// POST to Power Platform API
	resp, err := http.Post(apiURL, "application/json", strings.NewReader("{}"))
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

	// Find the first complete JSON object (in case of multiple responses)
	bodyStr := string(body)
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
		bodyStr = bodyStr[:endIdx]
	}

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

	log.Printf("Successfully fetched %d CVEs", len(cves))
	json.NewEncoder(w).Encode(cves)
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func main() {
	// Serve static files
	http.Handle("/", http.FileServer(http.Dir(".")))

	// API endpoint
	http.HandleFunc("/api/cves", fetchCVEs)

	log.Println("Server running at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}