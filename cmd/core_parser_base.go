// File: cmd/core_parser_base.go

package cmd

import (
    "strconv"
    "strings"
    "regexp"
    "path/filepath"
)

// parseInt safely converts string to int
func parseInt(s string) int {
    n, _ := strconv.Atoi(s)
    return n
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
    for _, line := range strings.Split(output, "\n") {
	// Use strings functions instead of regexp for better performance
	if strings.HasPrefix(line, "r") || strings.HasPrefix(line, "e") {
	    parts := strings.Fields(line)
	    if len(parts) >= 2 {
		registers[parts[0]] = strings.Join(parts[1:], " ")
	    }
	}
    }
    return registers
}

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

// getVisibleFrames extracts function names from a thread's backtrace text
func getVisibleFrames(threadInfo string) []string {
    var frames []string
    for _, line := range strings.Split(threadInfo, "\n") {
	if strings.Contains(line, "in ") {
	    if parts := strings.Split(line, "in "); len(parts) > 1 {
		frames = append(frames, strings.TrimSpace(parts[1]))
	    }
	}
    }
    return frames
}

// deduplicateThreads removes duplicate thread entries
func deduplicateThreads(threads []ThreadInfo) []ThreadInfo {
    seen := make(map[string]bool)
    var result []ThreadInfo

    for _, thread := range threads {
	if !seen[thread.ThreadID] {
	    seen[thread.ThreadID] = true
	    result = append(result, thread)
	}
    }
    return result
}

// findKeyFunction looks for meaningful function in backtrace
func findKeyFunction(backtrace []StackFrame) string {
    // Skip common system/runtime functions
    skipFuncs := map[string]bool{
	"raise": true,
	"clone": true,
	"start_thread": true,
	"poll": true,
	"select": true,
	"epoll_wait": true,
    }

    for _, frame := range backtrace {
	if !skipFuncs[frame.Function] && frame.Function != "??" {
	    return frame.Function
	}
    }
    return ""
}

// isSystemFunction determines if a function is a low-level system function
func isSystemFunction(funcName string) bool {
    systemPrefixes := []string{
	"std::",     // C++ standard library
	"__",        // Internal/compiler functions
	"_Z",        // Mangled names
	"pthread_",  // Threading functions
    }

    systemFunctions := map[string]bool{
	"main": true,
	"clone": true,
	"fork": true,
	"exec": true,
	"exit": true,
	"abort": true,
	"raise": true,
	"poll": true,
	"select": true,
	"read": true,
	"write": true,
    }

    if systemFunctions[funcName] {
	return true
    }

    for _, prefix := range systemPrefixes {
	if strings.HasPrefix(funcName, prefix) {
	    return true
	}
    }

    return false
}
