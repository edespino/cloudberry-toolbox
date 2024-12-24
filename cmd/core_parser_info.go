// File: cmd/core_parser_info.go

package cmd

import (
    "fmt"
    "regexp"
    "strings"
    "time"
)

// processTypes maps CloudBerry process types to descriptions
var processTypes = map[string]string{
    "coredw":    "Coordinator Write Process",
    "corerd":    "Coordinator Read Process",
    "primary":   "Primary Segment Process",
    "mirror":    "Mirror Segment Process",
    "master":    "Master Process",
    "standby":   "Standby Master Process",
}

// parseBasicInfo extracts structured information from the core file
func parseBasicInfo(fileInfo FileInfo) map[string]string {
    info := make(map[string]string)

    // Parse from file output
    if strings.Contains(fileInfo.FileOutput, "from ''") {
	parts := strings.Split(fileInfo.FileOutput, "from ''")
	if len(parts) > 1 {
	    cmdline := strings.Split(parts[1], "''")[0]
	    info["cmdline"] = cmdline

	    // Parse additional process details
	    extractProcessInfo(cmdline, info)
	}

	// Extract uid/gid information
	extractUserInfo(fileInfo.FileOutput, info)
    }

    // Add core file creation time in human-readable format
    if t, err := time.Parse(time.RFC3339, fileInfo.Created); err == nil {
	info["core_time"] = t.Format("2006-01-02 15:04:05 MST")
    }

    return info
}

func extractProcessInfo(cmdline string, info map[string]string) {
    // Extract basic postgres info
    if strings.HasPrefix(cmdline, "postgres:") {
	// Split on commas to handle different fields
	parts := strings.Split(cmdline, ",")
	for _, part := range strings.Fields(parts[0]) {
	    if part == "postgres:" {
		continue
	    }
	    info["database_id"] = strings.TrimSpace(part)
	    break
	}

	// Process type identification
	if strings.Contains(cmdline, "read_only coredw") {
	    info["process_type"] = "Coordinator Write (Read-Only Mode)"
	} else if strings.Contains(cmdline, "coredw") {
	    info["process_type"] = "Coordinator Write Process"
	} else if strings.Contains(cmdline, "corerd") {
	    info["process_type"] = "Coordinator Read Process"
	}

	// Extract various IDs using regular expressions
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

	// Extract client address with proper handling
	ipRE := regexp.MustCompile(`\s(\d+\.\d+\.\d+\.\d+)\s*\(`)
	if matches := ipRE.FindStringSubmatch(cmdline); matches != nil {
	    info["client_address"] = matches[1]
	}
    }

    // Add description
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

// enhanceProcessInfo adds additional context to the basic info
func enhanceProcessInfo(info map[string]string, analysis *CoreAnalysis) {
    // Add timestamp in human-readable format
    if t, err := time.Parse(time.RFC3339, analysis.Timestamp); err == nil {
	info["analysis_time"] = t.Format("2006-01-02 15:04:05 MST")
    }

    // Enhance process description
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

    // Add thread summary
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

// extractUserInfo parses user/group information from file output
func extractUserInfo(output string, info map[string]string) {
    patterns := []struct {
	pattern string
	key     string
    }{
	{`real uid: (\d+)`, "real_uid"},
	{`effective uid: (\d+)`, "effective_uid"},
	{`real gid: (\d+)`, "real_gid"},
	{`effective gid: (\d+)`, "effective_gid"},
    }

    for _, p := range patterns {
	re := regexp.MustCompile(p.pattern)
	if matches := re.FindStringSubmatch(output); matches != nil {
	    info[p.key] = matches[1]
	}
    }
}

// getProcessDetails provides a human-readable summary of the process
func getProcessDetails(info map[string]string) string {
    var details strings.Builder

    // Start with process type if available
    if procType := info["process_type"]; procType != "" {
	details.WriteString(procType)
    } else {
	details.WriteString("PostgreSQL Process")
    }

    // Add database and connection info
    if dbID := info["database_id"]; dbID != "" {
	details.WriteString(fmt.Sprintf(" (DB: %s", dbID))
	if connID := info["connection_id"]; connID != "" {
	    details.WriteString(fmt.Sprintf(", Conn: %s", connID))
	}
	details.WriteString(")")
    }

    // Add segment info for segment processes
    if segID := info["segment_id"]; segID != "" {
	details.WriteString(fmt.Sprintf(" on segment %s", segID))
    }

    // Add client address if available
    if addr := info["client_addr"]; addr != "" {
	details.WriteString(fmt.Sprintf(" from %s", addr))
    }

    return details.String()
}

// analyzeCrashContext provides context about the crash environment
func analyzeCrashContext(analysis *CoreAnalysis) string {
    var context strings.Builder

    // Add process identification
    if details := getProcessDetails(analysis.BasicInfo); details != "" {
	context.WriteString(details)
	context.WriteString("\n")
    }

    // Add timing information
    if coreTime := analysis.BasicInfo["core_time"]; coreTime != "" {
	context.WriteString(fmt.Sprintf("Core dumped at: %s\n", coreTime))
    }

    // Add thread context
    var activeThreads int
    var crashedThread string
    for _, thread := range analysis.Threads {
	activeThreads++
	if thread.IsCrashed {
	    crashedThread = thread.Name
	}
    }
    context.WriteString(fmt.Sprintf("Active threads: %d\n", activeThreads))
    if crashedThread != "" {
	context.WriteString(fmt.Sprintf("Crash occurred in: %s\n", crashedThread))
    }

    // Add query context if available
    if cmdID := analysis.BasicInfo["command_id"]; cmdID != "" {
	context.WriteString(fmt.Sprintf("Command ID: %s\n", cmdID))
    }
    if sliceID := analysis.BasicInfo["slice_id"]; sliceID != "" {
	context.WriteString(fmt.Sprintf("Slice ID: %s\n", sliceID))
    }

    return context.String()
}
