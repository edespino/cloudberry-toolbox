// File: cmd/core_parser_base.go

package cmd

import (
    "strconv"
    "strings"
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

// extractAddress safely extracts and standardizes hex addresses
func extractAddress(addr string) string {
    if strings.HasPrefix(addr, "0x") {
	return addr
    }
    if addr == "" {
	return "0x0"
    }
    return "0x" + strings.TrimLeft(addr, "0")
}

// containsAny checks if any of the strings in needles is in haystack
func containsAny(haystack string, needles []string) bool {
    for _, needle := range needles {
	if strings.Contains(haystack, needle) {
	    return true
	}
    }
    return false
}

// parseCallStack extracts a clean call stack from backtrace
func parseCallStack(backtrace []StackFrame) []string {
    var stack []string
    for _, frame := range backtrace {
	if frame.Function != "??" {
	    stack = append(stack, frame.Function)
	}
    }
    return stack
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

// parseRegisters extracts register information from GDB output
func parseRegisters(output string) map[string]string {
    registers := make(map[string]string)
    regPattern := `^([re][a-z][a-z]|r\d+|[cdefgs]s|[re]ip|[re]flags)\s+(.+)`

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
