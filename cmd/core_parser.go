// File: cmd/core_parser.go
package cmd

// Update the imports section in cmd/core_parser.go

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// determineThreadRole identifies PostgreSQL thread roles
func determineThreadRole(threadInfo string) string {
	patterns := map[string]string{
		`(?i)postmaster`:   "Postmaster",
		`(?i)bgwriter`:     "Background Writer",
		`(?i)checkpointer`: "Checkpointer",
		`(?i)walwriter`:    "WAL Writer",
		`(?i)autovacuum`:   "Autovacuum Worker",
		`(?i)stats`:        "Stats Collector",
		`(?i)launcher`:     "AV Launcher",
		`(?i)seqserver`:    "Sequence Server",
		`(?i)ftsprobe`:     "FTS Probe",
	}

	for pattern, role := range patterns {
		if matched, _ := regexp.MatchString(pattern, threadInfo); matched {
			return role
		}
	}
	return "Unknown"
}

// parseThreads extracts thread information from GDB output
func parseThreads(output string) []ThreadInfo {
	var threads []ThreadInfo
	var currentThread *ThreadInfo
	threadRE := regexp.MustCompile(`Thread\s+(\d+)\s+\(.*?(?:LWP\s+(\d+)|Thread[^)]+)\)(?:\s*\[(.*?)\])?`)

	for _, line := range strings.Split(output, "\n") {
		if matches := threadRE.FindStringSubmatch(line); matches != nil {
			if currentThread != nil {
				threads = append(threads, *currentThread)
			}

			threadRole := determineThreadRole(line)

			currentThread = &ThreadInfo{
				ThreadID:  matches[1],
				LWPID:     matches[2],
				Name:      threadRole,
				State:     matches[3],
				IsCrashed: strings.Contains(line, "* "), // GDB marks crashed thread with asterisk
			}
		} else if currentThread != nil && strings.HasPrefix(line, "#") {
			frame := parseStackFrame(line)
			if frame != nil {
				// Try to get source file and line number
				if srcMatch := regexp.MustCompile(`at ([^:]+):(\d+)`).FindStringSubmatch(line); srcMatch != nil {
					frame.SourceFile = srcMatch[1]
					frame.LineNumber, _ = strconv.Atoi(srcMatch[2])
				}

				// Try to get module name
				if modMatch := regexp.MustCompile(`from ([^)]+)`).FindStringSubmatch(line); modMatch != nil {
					frame.Module = filepath.Base(modMatch[1])
				}

				currentThread.Backtrace = append(currentThread.Backtrace, *frame)
			}
		}
	}

	if currentThread != nil {
		threads = append(threads, *currentThread)
	}

	return threads
}

// parseStackFrame parses a single stack frame
func parseStackFrame(line string) *StackFrame {
	frameRE := regexp.MustCompile(`#(\d+)\s+([^in]+)in\s+(\S+)\s*\(([^)]*)\)`)
	if matches := frameRE.FindStringSubmatch(line); matches != nil {
		frame := &StackFrame{
			FrameNum:  matches[1],
			Location:  strings.TrimSpace(matches[2]),
			Function:  matches[3],
			Arguments: matches[4],
		}

		// Try to parse local variables if available
		localsRE := regexp.MustCompile(`locals = {([^}]+)}`)
		if localMatch := localsRE.FindStringSubmatch(line); localMatch != nil {
			frame.Locals = parseLocals(localMatch[1])
		}

		return frame
	}
	return nil
}

// parseLocals parses local variables from GDB output
func parseLocals(localsStr string) map[string]string {
	locals := make(map[string]string)
	pairs := strings.Split(localsStr, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			locals[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return locals
}

// parseRegisters extracts register information from GDB output
func parseRegisters(output string) map[string]string {
	registers := make(map[string]string)
	regRE := regexp.MustCompile(`^([re][a-z][a-z]|r\d+|[cdefgs]s|[re]ip|[re]flags)\s+(.+)`)

	for _, line := range strings.Split(output, "\n") {
		if matches := regRE.FindStringSubmatch(line); matches != nil {
			registers[matches[1]] = strings.TrimSpace(matches[2])
		}
	}
	return registers
}

// parseSignalInfo extracts signal information from GDB output
func parseSignalInfo(output string) SignalInfo {
	info := SignalInfo{}
	siginfoRE := regexp.MustCompile(`si_signo = (\d+).*?si_code = (\d+)`)
	addrRE := regexp.MustCompile(`si_addr = (0x[0-9a-fA-F]+)`)
	signalRE := regexp.MustCompile(`Signal\s+(\d+)\s+\(([A-Z]+)\)`)

	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "$_siginfo =") {
			if matches := siginfoRE.FindStringSubmatch(line); matches != nil {
				info.SignalNumber = parseInt(matches[1])
				info.SignalCode = parseInt(matches[2])
				info.SignalName = getSignalName(info.SignalNumber)
				info.SignalDescription = getSignalDescription(info.SignalNumber, info.SignalCode)
			}
			if matches := addrRE.FindStringSubmatch(line); matches != nil {
				info.FaultAddress = matches[1]
			}
		} else if matches := signalRE.FindStringSubmatch(line); matches != nil && info.SignalName == "" {
			info.SignalNumber = parseInt(matches[1])
			info.SignalName = matches[2]
			info.SignalDescription = getSignalDescription(info.SignalNumber, 0)
		}
	}

	return info
}

// getSignalName converts signal number to name
func getSignalName(signo int) string {
	signals := map[int]string{
		1:  "SIGHUP",
		2:  "SIGINT",
		3:  "SIGQUIT",
		4:  "SIGILL",
		6:  "SIGABRT",
		8:  "SIGFPE",
		9:  "SIGKILL",
		11: "SIGSEGV",
		13: "SIGPIPE",
		14: "SIGALRM",
		15: "SIGTERM",
	}
	if name, ok := signals[signo]; ok {
		return name
	}
	return fmt.Sprintf("SIGNAL_%d", signo)
}

// getSignalDescription returns human-readable signal description
func getSignalDescription(signo, code int) string {
	switch signo {
	case 11: // SIGSEGV
		codes := map[int]string{
			1: "SEGV_MAPERR (Address not mapped to object)",
			2: "SEGV_ACCERR (Invalid permissions for mapped object)",
			3: "SEGV_BNDERR (Failed address bound checks)",
			4: "SEGV_PKUERR (Access was denied by memory protection keys)",
		}
		if desc, ok := codes[code]; ok {
			return desc
		}
		return fmt.Sprintf("SIGSEGV with code %d", code)

	case 6: // SIGABRT
		return "Process abort signal (possibly assertion failure)"

	case 7: // SIGBUS
		codes := map[int]string{
			1: "BUS_ADRALN (Invalid address alignment)",
			2: "BUS_ADRERR (Nonexistent physical address)",
			3: "BUS_OBJERR (Object-specific hardware error)",
		}
		if desc, ok := codes[code]; ok {
			return desc
		}
		return fmt.Sprintf("SIGBUS with code %d", code)

	case 8: // SIGFPE
		codes := map[int]string{
			1: "FPE_INTDIV (Integer divide by zero)",
			2: "FPE_INTOVF (Integer overflow)",
			3: "FPE_FLTDIV (Floating point divide by zero)",
			4: "FPE_FLTOVF (Floating point overflow)",
			5: "FPE_FLTUND (Floating point underflow)",
			6: "FPE_FLTRES (Floating point inexact result)",
			7: "FPE_FLTINV (Invalid floating point operation)",
			8: "FPE_FLTSUB (Subscript out of range)",
		}
		if desc, ok := codes[code]; ok {
			return desc
		}
		return fmt.Sprintf("SIGFPE with code %d", code)
	}

	return fmt.Sprintf("Signal %d with code %d", signo, code)
}

// parseSharedLibraries extracts shared library information from GDB output
func parseSharedLibraries(output string) []LibraryInfo {
	var libraries []LibraryInfo
	libraryRE := regexp.MustCompile(`(?m)^(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\w+)\s+(.+?\.so[.0-9]*)`)

	for _, line := range strings.Split(output, "\n") {
		if matches := libraryRE.FindStringSubmatch(line); matches != nil {
			startAddr := matches[1]
			endAddr := matches[2]
			loadStatus := matches[3]
			libPath := matches[4]

			libraries = append(libraries, LibraryInfo{
				Name:      libPath,
				StartAddr: startAddr,
				EndAddr:   endAddr,
				Version:   getLibraryVersion(libPath),
				Type:      categorizeLibrary(libPath),
				IsLoaded:  loadStatus == "Yes",
				TextStart: startAddr,
				TextEnd:   endAddr,
			})
		}
	}

	return libraries
}

// categorizeLibrary determines the type of shared library
func categorizeLibrary(path string) string {
	if strings.Contains(path, "libpostgres") {
		return "Core"
	} else if strings.Contains(path, "postgresql") {
		return "Extension"
	} else if strings.Contains(path, "/lib") {
		return "System"
	}
	return "Other"
}

// getLibraryVersion attempts to extract version from library name
func getLibraryVersion(libPath string) string {
	verMatch := regexp.MustCompile(`\.so[.]([0-9.]+)$`).FindStringSubmatch(libPath)
	if verMatch != nil {
		return verMatch[1]
	}
	return ""
}

// parseInt safely converts string to int
func parseInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// saveAnalysis saves analysis results to a file
func saveAnalysis(analysis CoreAnalysis) error {
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(outputDir, fmt.Sprintf("core_analysis_%s.%s", timestamp, formatFlag))

	var data []byte
	var err error
	if formatFlag == "json" {
		data, err = json.MarshalIndent(analysis, "", "  ")
	} else {
		data, err = yaml.Marshal(analysis)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal analysis: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write analysis file: %w", err)
	}

	fmt.Printf("Analysis saved to: %s\n", filename)
	return nil
}

// saveComparison saves comparison results to a file
func saveComparison(comparison CoreComparison) error {
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(outputDir, fmt.Sprintf("core_comparison_%s.%s", timestamp, formatFlag))

	var data []byte
	var err error
	if formatFlag == "json" {
		data, err = json.MarshalIndent(comparison, "", "  ")
	} else {
		data, err = yaml.Marshal(comparison)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal comparison: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write comparison file: %w", err)
	}

	fmt.Printf("Comparison results saved to: %s\n", filename)
	return nil
}

// Add this function to cmd/core_parser.go

// compareCores analyzes multiple core files to identify patterns
func compareCores(analyses []CoreAnalysis) CoreComparison {
	comparison := CoreComparison{
		TotalCores:      len(analyses),
		CommonSignals:   make(map[string]int),
		CommonFunctions: make(map[string]int),
		TimeRange:       make(map[string]string),
	}

	// Track time range
	var firstTime, lastTime time.Time
	for i, analysis := range analyses {
		t, _ := time.Parse(time.RFC3339, analysis.Timestamp)
		if i == 0 || t.Before(firstTime) {
			firstTime = t
		}
		if i == 0 || t.After(lastTime) {
			lastTime = t
		}
	}
	comparison.TimeRange["first"] = firstTime.Format(time.RFC3339)
	comparison.TimeRange["last"] = lastTime.Format(time.RFC3339)

	// Collect signal and function distributions
	crashGroups := make(map[string][]CoreAnalysis)
	for _, analysis := range analyses {
		signal := analysis.SignalInfo.SignalName
		comparison.CommonSignals[signal]++

		// Count functions in stack traces
		for _, frame := range analysis.StackTrace {
			comparison.CommonFunctions[frame.Function]++
		}

		// Create crash signature
		var signature strings.Builder
		signature.WriteString(signal)
		for i, frame := range analysis.StackTrace {
			if i < 3 { // Use top 3 frames for signature
				signature.WriteString("|" + frame.Function)
			}
		}
		crashGroups[signature.String()] = append(crashGroups[signature.String()], analysis)
	}

	// Generate crash patterns
	for signature, group := range crashGroups {
		if len(group) > 1 { // Only include patterns that occur multiple times
			parts := strings.Split(signature, "|")
			pattern := CrashPattern{
				Signal:         parts[0],
				StackSignature: parts[1:],
				OccurrenceCount: len(group),
			}
			for _, analysis := range group {
				pattern.AffectedCoreFiles = append(pattern.AffectedCoreFiles, analysis.CoreFile)
			}
			comparison.CrashPatterns = append(comparison.CrashPatterns, pattern)
		}
	}

	// Sort patterns by occurrence count
	sort.Slice(comparison.CrashPatterns, func(i, j int) bool {
		return comparison.CrashPatterns[i].OccurrenceCount > comparison.CrashPatterns[j].OccurrenceCount
	})

	return comparison
}

// Add this function to cmd/core_parser.go

// parseStackTrace extracts stack trace information from GDB output
func parseStackTrace(output string) []StackFrame {
	var frames []StackFrame
	stackRE := regexp.MustCompile(`#(\d+)\s+([^in]+)in\s+(\S+)\s*\(([^)]*)\)`)

	inStackTrace := false
	for _, line := range strings.Split(output, "\n") {
		// Look for the start of a stack trace
		if strings.HasPrefix(line, "Thread") {
			inStackTrace = true
			continue
		}

		// Process frames while in a stack trace
		if inStackTrace && strings.HasPrefix(line, "#") {
			if matches := stackRE.FindStringSubmatch(line); matches != nil {
				frame := StackFrame{
					FrameNum:  matches[1],
					Location:  strings.TrimSpace(matches[2]),
					Function:  matches[3],
					Arguments: matches[4],
				}

				// Try to get source file and line number
				if srcMatch := regexp.MustCompile(`at ([^:]+):(\d+)`).FindStringSubmatch(line); srcMatch != nil {
					frame.SourceFile = srcMatch[1]
					frame.LineNumber, _ = strconv.Atoi(srcMatch[2])
				}

				// Try to get module name
				if modMatch := regexp.MustCompile(`from ([^)]+)`).FindStringSubmatch(line); modMatch != nil {
					frame.Module = filepath.Base(modMatch[1])
				}

				frames = append(frames, frame)
			}
		}

		// End of stack trace
		if inStackTrace && line == "" {
			inStackTrace = false
		}
	}

	return frames
}
