// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// File: cmd/core_parser_base.go
// Purpose: Provides base parsing utilities for GDB output, such as extracting stack traces, registers,
// threads, and other relevant information. These functions form the foundational utilities used
// for core dump analysis.
// Dependencies: Relies on standard Go libraries for string manipulation, regular expressions, and path operations.

package cmd

import (
    "strconv"
    "strings"
    "regexp"
    "path/filepath"
)

// parseInt safely converts a string to an integer.
// Parameters:
// - s: The string to convert.
// Returns:
// - The integer representation of the string, or 0 if the conversion fails.
func parseInt(s string) int {
    n, _ := strconv.Atoi(s)
    return n
}

// parseLocals parses local variables from GDB output.
// Parameters:
// - localsStr: The raw string containing local variables.
// Returns:
// - A map of variable names to their corresponding values.
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

// parseRegisters extracts register information from GDB output.
// Parameters:
// - output: The raw GDB output containing register data.
// Returns:
// - A map of register names to their values.
func parseRegisters(output string) map[string]string {
    registers := make(map[string]string)
    for _, line := range strings.Split(output, "\n") {
	if strings.HasPrefix(line, "r") || strings.HasPrefix(line, "e") {
	    parts := strings.Fields(line)
	    if len(parts) >= 2 {
		registers[parts[0]] = strings.Join(parts[1:], " ")
	    }
	}
    }
    return registers
}

// parseStackTrace extracts stack trace information from GDB output.
// Parameters:
// - output: The raw GDB output containing stack trace data.
// Returns:
// - A slice of `StackFrame` objects representing the parsed stack trace.
func parseStackTrace(output string) []StackFrame {
    var frames []StackFrame
    stackRE := regexp.MustCompile(`#(\d+)\s+([^in]+)in\s+(\S+)\s*\(([^)]*)\)`)

    inStackTrace := false
    for _, line := range strings.Split(output, "\n") {
	if strings.HasPrefix(line, "Thread") {
	    inStackTrace = true
	    continue
	}

	if inStackTrace && strings.HasPrefix(line, "#") {
	    if matches := stackRE.FindStringSubmatch(line); matches != nil {
		frame := StackFrame{
		    FrameNum:  matches[1],
		    Location:  strings.TrimSpace(matches[2]),
		    Function:  matches[3],
		    Arguments: matches[4],
		}

		if srcMatch := regexp.MustCompile(`at ([^:]+):(\d+)`).FindStringSubmatch(line); srcMatch != nil {
		    frame.SourceFile = srcMatch[1]
		    frame.LineNumber, _ = strconv.Atoi(srcMatch[2])
		}

		if modMatch := regexp.MustCompile(`from ([^)]+)`).FindStringSubmatch(line); modMatch != nil {
		    frame.Module = filepath.Base(modMatch[1])
		}

		frames = append(frames, frame)
	    }
	}

	if inStackTrace && line == "" {
	    inStackTrace = false
	}
    }

    return frames
}

// getVisibleFrames extracts function names from a thread's backtrace text.
// Parameters:
// - threadInfo: The raw string containing the thread's backtrace.
// Returns:
// - A slice of function names visible in the backtrace.
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

// deduplicateThreads removes duplicate thread entries from a list.
// Parameters:
// - threads: A slice of `ThreadInfo` objects representing thread data.
// Returns:
// - A deduplicated slice of `ThreadInfo` objects.
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

// findKeyFunction looks for a meaningful function in a backtrace.
// Parameters:
// - backtrace: A slice of `StackFrame` objects representing the backtrace.
// Returns:
// - The name of a key function in the backtrace, excluding common runtime/system functions.
func findKeyFunction(backtrace []StackFrame) string {
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

// isSystemFunction determines if a function is a low-level system function.
// Parameters:
// - funcName: The name of the function to check.
// Returns:
// - True if the function is considered a system-level function, false otherwise.
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

// parseCallStack extracts a clean call stack from a backtrace.
// Parameters:
// - backtrace: A slice of `StackFrame` objects representing the backtrace.
// Returns:
// - A slice of strings representing the clean call stack.
func parseCallStack(backtrace []StackFrame) []string {
    var stack []string
    for _, frame := range backtrace {
	if frame.Function != "??" {
	    stack = append(stack, frame.Function)
	}
    }
    return stack
}

// containsAny checks if any of the strings in a list appear in a given text.
// Parameters:
// - haystack: The string to search within.
// - needles: A slice of strings to search for.
// Returns:
// - True if any of the strings in `needles` are found in `haystack`, false otherwise.
func containsAny(haystack string, needles []string) bool {
    for _, needle := range needles {
	if strings.Contains(haystack, needle) {
	    return true
	}
    }
    return false
}
