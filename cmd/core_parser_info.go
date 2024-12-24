// File: cmd/core_parser_info.go
// Purpose: Provides utilities to extract and process PostgreSQL/CloudBerry process information
// from core dumps and GDB output. Includes methods for parsing basic information, enhancing
// process context, and generating human-readable descriptions of the crash environment.
// Dependencies: Relies on Go's standard libraries for string manipulation, regex operations, and time handling.

package cmd

import (
    "fmt"
    "regexp"
    "strings"
    "time"
)

// processTypes maps CloudBerry process types to descriptions.
var processTypes = map[string]string{
    "coredw":    "Coordinator Write Process",
    "corerd":    "Coordinator Read Process",
    "primary":   "Primary Segment Process",
    "mirror":    "Mirror Segment Process",
    "master":    "Master Process",
    "standby":   "Standby Master Process",
}

// parseBasicInfo extracts and populates the basic_info section.
// Parameters:
// - fileOutput: The raw output from the core dump file analysis.
// Returns:
// - A map containing key-value pairs of extracted process details.
func parseBasicInfo(fileOutput string) map[string]string {
    info := make(map[string]string)

    // Patterns for extracting data
    patterns := map[string]*regexp.Regexp{
	"database_id":    regexp.MustCompile(`postgres:\s+(\d+)`),
	"segment_id":     regexp.MustCompile(`seg(\d+)`),
	"connection_id":  regexp.MustCompile(`con(\d+)`),
	"command_id":     regexp.MustCompile(`cmd(\d+)`),
	"client_pid":     regexp.MustCompile(`\((\d+)\)`),
	"client_address": regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`),
    }

    // Extract data using patterns
    for key, re := range patterns {
	if matches := re.FindStringSubmatch(fileOutput); matches != nil && len(matches) > 1 {
	    info[key] = matches[1]
	} else {
	    info[key] = "N/A" // Assign a default value for missing matches
	}
    }

    // Extract core_time (assumed to be present in the file output as a timestamp)
    if matches := regexp.MustCompile(`created:\s+"([\d\-:T\sZ]+)"`).FindStringSubmatch(fileOutput); matches != nil {
	info["core_time"] = matches[1]
    } else {
	info["core_time"] = "N/A"
    }

    // Additional derived fields
    if _, ok := info["database_id"]; ok {
	info["description"] = fmt.Sprintf(
	    "Coordinator Write (Read-Only Mode), Database %s, Segment %s, Connection %s, Client %s (PID %s)",
	    info["database_id"], info["segment_id"], info["connection_id"], info["client_address"], info["client_pid"],
	)
	info["process_type"] = "Coordinator Write (Read-Only Mode)"
    }

    return info
}

// extractProcessInfo populates process information based on the command line.
// Parameters:
// - cmdline: The command-line string of the PostgreSQL/CloudBerry process.
// - info: A map to store extracted process details.
func extractProcessInfo(cmdline string, info map[string]string) {
    if strings.HasPrefix(cmdline, "postgres:") {
	parts := strings.Split(cmdline, ",")
	for _, part := range strings.Fields(parts[0]) {
	    if part == "postgres:" {
		continue
	    }
	    info["database_id"] = strings.TrimSpace(part)
	    break
	}

	if strings.Contains(cmdline, "read_only coredw") {
	    info["process_type"] = "Coordinator Write (Read-Only Mode)"
	} else if strings.Contains(cmdline, "coredw") {
	    info["process_type"] = "Coordinator Write Process"
	} else if strings.Contains(cmdline, "corerd") {
	    info["process_type"] = "Coordinator Read Process"
	}

	patterns := map[string]*regexp.Regexp{
	    "segment_id": regexp.MustCompile(`seg(\d+)`),
	    "connection_id": regexp.MustCompile(`con(\d+)`),
	    "command_id": regexp.MustCompile(`cmd(\d+)`),
	    "slice_id": regexp.MustCompile(`slice(\d+)`),
	    "client_pid": regexp.MustCompile(`\((\d+)\)`),
	}

	for key, re := range patterns {
	    if matches := re.FindStringSubmatch(cmdline); matches != nil {
		info[key] = matches[1]
	    }
	}

	ipRE := regexp.MustCompile(`\s(\d+\.\d+\.\d+\.\d+)\s*\(`)
	if matches := ipRE.FindStringSubmatch(cmdline); matches != nil {
	    info["client_address"] = matches[1]
	}
    }

    var desc []string
    if procType := info["process_type"]; procType != "" {
	desc = append(desc, procType)
    }
    if dbID := info["database_id"]; dbID != "" {
	desc = append(desc, fmt.Sprintf("Database %s", dbID))
    }
    if segID := info["segment_id"]; segID != "" {
	desc = append(desc, fmt.Sprintf("Segment %s", segID))
    }
    if connID := info["connection_id"]; connID != "" {
	desc = append(desc, fmt.Sprintf("Connection %s", connID))
    }
    if addr := info["client_address"]; addr != "" {
	if pid := info["client_pid"]; pid != "" {
	    desc = append(desc, fmt.Sprintf("Client %s (PID %s)", addr, pid))
	} else {
	    desc = append(desc, fmt.Sprintf("Client %s", addr))
	}
    }

    if len(desc) > 0 {
	info["description"] = strings.Join(desc, ", ")
    }
}

// enhanceProcessInfo adds additional context to the basic info.
// Parameters:
// - info: A map of process details.
// - analysis: The CoreAnalysis object containing the process data.
func enhanceProcessInfo(info map[string]string, analysis *CoreAnalysis) {
    if t, err := time.Parse(time.RFC3339, analysis.Timestamp); err == nil {
	info["analysis_time"] = t.Format("2006-01-02 15:04:05 MST")
    }

    var description []string
    if procType := info["process_type"]; procType != "" {
	description = append(description, procType)
    }
    if dbID := info["database_id"]; dbID != "" {
	description = append(description, fmt.Sprintf("DB %s", dbID))
    }
    if segID := info["segment_id"]; segID != "" {
	description = append(description, fmt.Sprintf("segment %s", segID))
    }
    if address := info["client_address"]; address != "" {
	if pid := info["client_pid"]; pid != "" {
	    description = append(description, fmt.Sprintf("client %s (pid %s)", address, pid))
	} else {
	    description = append(description, fmt.Sprintf("client %s", address))
	}
    }
    if len(description) > 0 {
	info["process_description"] = strings.Join(description, ", ")
    }

    threadCount := make(map[string]int)
    for _, thread := range analysis.Threads {
	threadCount[thread.Name]++
    }
    var threadSummary []string
    for name, count := range threadCount {
	if count > 1 {
	    threadSummary = append(threadSummary, fmt.Sprintf("%dx %s", count, name))
	} else {
	    threadSummary = append(threadSummary, name)
	}
    }
    if len(threadSummary) > 0 {
	info["thread_summary"] = strings.Join(threadSummary, ", ")
    }
}

// extractUserInfo parses user/group information from file output.
// Parameters:
// - output: The raw output from the core dump analysis.
// - info: A map to store extracted user/group details.
func extractUserInfo(output string, info map[string]string) {
    patterns := []struct {
	pattern string
	key     string
    }{
	{"real uid: (\d+)", "real_uid"},
	{"effective uid: (\d+)", "effective_uid"},
	{"real gid: (\d+)", "real_gid"},
	{"effective gid: (\d+)", "effective_gid"},
    }

    for _, p := range patterns {
	re := regexp.MustCompile(p.pattern)
	if matches := re.FindStringSubmatch(output); matches != nil {
	    info[p.key] = matches[1]
	}
    }
}

// getProcessDetails provides a human-readable summary of the process.
// Parameters:
// - info: A map containing process details.
// Returns:
// - A string summarizing the process details.
func getProcessDetails(info map[string]string) string {
    var details strings.Builder

    if procType := info["process_type"]; procType != "" {
	details.WriteString(procType)
    } else {
	details.WriteString("PostgreSQL Process")
    }

    if dbID := info["database_id"]; dbID != "" {
	details.WriteString(fmt.Sprintf(" (DB: %s", dbID))
	if connID := info["connection_id"]; connID != "" {
	    details.WriteString(fmt.Sprintf(", Conn: %s", connID))
	}
	details.WriteString(")")
    }

    if segID := info["segment_id"]; segID != "" {
	details.WriteString(fmt.Sprintf(" on segment %s", segID))
    }

    if addr := info["client_addr"]; addr != "" {
	details.WriteString(fmt.Sprintf(" from %s", addr))
    }

    return details.String()
}
