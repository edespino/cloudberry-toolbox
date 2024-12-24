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

// extractProcessInfo parses CloudBerry process details from command line
func extractProcessInfo(cmdline string, info map[string]string) {
    // Extract basic postgres info
    if strings.HasPrefix(cmdline, "postgres:") {
	fields := strings.Fields(cmdline)
	for i, field := range fields {
	    if field == "postgres:" && i+1 < len(fields) {
		info["database_id"] = strings.TrimSuffix(fields[i+1], ",")
	    }
	}

	// Parse process type
	for procType, desc := range processTypes {
	    if strings.Contains(cmdline, procType) {
		info["process_type"] = desc
		break
	    }
	}

	// Extract connection info
	patterns := map[string]string{
	    `seg(\d+)`:     "segment_id",
	    `con(\d+)`:     "connection_id",
	    `cmd(\d+)`:     "command_id",
	    `slice(\d+)`:   "slice_id",
	    `(\d+\.\d+\.\d+\.\d+)`: "client_addr",
	}

	for pattern, key := range patterns {
	    re := regexp.MustCompile(pattern)
	    if matches := re.FindStringSubmatch(cmdline); matches != nil {
		info[key] = matches[1]
	    }
	}

	// Extract transaction info if present
	if strings.Contains(cmdline, "xact") {
	    xactRE := regexp.MustCompile(`xact[^\s]*\s+(\d+)`)
	    if matches := xactRE.FindStringSubmatch(cmdline); matches != nil {
		info["transaction_id"] = matches[1]
	    }
	}
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
