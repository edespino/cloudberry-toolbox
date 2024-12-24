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

// File: cmd/core_parser_threads.go
// Purpose: Provides utilities for parsing and analyzing thread information from GDB output.
// Includes methods to extract thread details, enhance context, and summarize thread activities
// in CloudBerry processes.
// Dependencies: Utilizes Go's standard libraries for regex, string manipulation, and formatting.

package cmd

import (
    "fmt"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"
)

// threadPatterns defines known PostgreSQL/CloudBerry thread patterns.
var threadPatterns = map[string]string{
    `(?i)postmaster`:      "Postmaster",
    `(?i)bgwriter`:        "Background Writer",
    `(?i)checkpointer`:    "Checkpointer",
    `(?i)walwriter`:       "WAL Writer",
    `(?i)autovacuum`:      "Autovacuum Worker",
    `(?i)stats`:           "Stats Collector",
    `(?i)launcher`:        "AV Launcher",
    `(?i)rxThreadFunc`:    "Interconnect RX",
    `(?i)txThreadFunc`:    "Interconnect TX",
    `(?i)executor`:        "Query Executor",
    `(?i)cdbgang`:         "Gang Worker",
    `(?i)distributor`:     "Motion Node",
    `(?i)fts`:             "FTS Probe",
    `(?i)ftsprobe`:        "FTS Probe",
    `(?i)rg_worker`:       "Resource Group Worker",
    `(?i)seqserver`:       "Sequence Server",
    `(?i)motionlauncher`:  "Motion Launcher",
    `(?i)resgroup`:        "Resource Group",
    `(?i)backendmain`:     "Backend Worker",
    `(?i)startup`:         "Startup Process",
    `(?i)logger`:          "Logger Process",
}

// parseCurrentInstruction extracts the current instruction from GDB output.
// Parameters:
// - output: The raw GDB output containing instruction details.
// Returns:
// - A string representing the current instruction, or an empty string if not found.
func parseCurrentInstruction(output string) string {
    instRE := regexp.MustCompile(`=>\s+(0x[0-9a-f]+\s+<[^>]+>:.+)`)
    if matches := instRE.FindStringSubmatch(output); matches != nil {
	return matches[1]
    }
    return ""
}

// parseStackFrame parses a single stack frame from GDB output.
// Parameters:
// - line: The raw string representing a single stack frame.
// Returns:
// - A pointer to a StackFrame object with parsed details, or nil if parsing fails.
func parseStackFrame(line string) *StackFrame {
    frameRE := regexp.MustCompile(`#(\d+)\s+([^in]+)in\s+(\S+)\s*\(([^)]*)\)`)
    if matches := frameRE.FindStringSubmatch(line); matches != nil {
	frame := &StackFrame{
	    FrameNum:  matches[1],
	    Location:  strings.TrimSpace(matches[2]),
	    Function:  matches[3],
	    Arguments: matches[4],
	}

	// Extract source file and line number.
	if srcMatch := regexp.MustCompile(`at ([^:]+):(\d+)`).FindStringSubmatch(line); srcMatch != nil {
	    frame.SourceFile = srcMatch[1]
	    frame.LineNumber, _ = strconv.Atoi(srcMatch[2])
	}

	// Extract module name.
	if modMatch := regexp.MustCompile(`from ([^)]+)`).FindStringSubmatch(line); modMatch != nil {
	    frame.Module = filepath.Base(modMatch[1])
	}

	// Parse local variables if available.
	if localsMatch := regexp.MustCompile(`locals = {([^}]+)}`).FindStringSubmatch(line); localsMatch != nil {
	    frame.Locals = parseLocals(localsMatch[1])
	}

	return frame
    }
    return nil
}

// enhanceThreadInfo adds additional context to thread information.
// Parameters:
// - thread: A ThreadInfo object representing a thread.
// Returns:
// - An updated ThreadInfo object with enhanced context.
func enhanceThreadInfo(thread ThreadInfo) ThreadInfo {
    // Determine thread role from backtrace.
    thread.Name = determineThreadRole(thread.Backtrace)

    // Add context about crashed state.
    if thread.IsCrashed {
	thread.State = fmt.Sprintf("%s (Crashed)", thread.State)
    }

    // Add query context if available.
    for _, frame := range thread.Backtrace {
	if queryInfo, ok := frame.Locals["queryDesc"]; ok {
	    thread.Name = fmt.Sprintf("%s (Query: %s)", thread.Name, queryInfo)
	    break
	}
    }

    return thread
}

// determineThreadRole identifies the role of a thread based on its backtrace.
// Parameters:
// - backtrace: A slice of StackFrame objects representing the thread's backtrace.
// Returns:
// - A string representing the thread's role, or an empty string if not identified.
func determineThreadRole(backtrace []StackFrame) string {
    // Check for signal handler.
    for _, frame := range backtrace {
	if strings.Contains(frame.Function, "SigillSigsegvSigbus") {
	    return "Signal Handler"
	}
    }

    // Check specific functions in backtrace.
    for _, frame := range backtrace {
	if strings.Contains(frame.Function, "rxThreadFunc") {
	    return "Interconnect RX"
	}
	if strings.Contains(frame.Function, "txThreadFunc") {
	    return "Interconnect TX"
	}
    }

    return ""
}

// parseThreads extracts thread information from GDB output.
// Parameters:
// - output: The raw GDB output containing thread details.
// Returns:
// - A slice of ThreadInfo objects representing the parsed threads.
func parseThreads(output string) []ThreadInfo {
    var threads []ThreadInfo
    var currentThread *ThreadInfo
    threadRE := regexp.MustCompile(`Thread\s+(\d+)\s+(?:\(Thread\s+(?:0x[0-9a-f]+)\s+)?(?:\(LWP\s+(\d+)\))?`)

    for _, line := range strings.Split(output, "\n") {
	if matches := threadRE.FindStringSubmatch(line); matches != nil {
	    if currentThread != nil {
		// Determine thread role based on backtrace before adding.
		currentThread.Name = determineThreadRole(currentThread.Backtrace)
		threads = append(threads, *currentThread)
	    }

	    currentThread = &ThreadInfo{
		ThreadID:   matches[1],
		LWPID:      matches[2],
		IsCrashed:  strings.Contains(line, "* "),
	    }
	} else if currentThread != nil && strings.HasPrefix(line, "#") {
	    frame := parseStackFrame(line)
	    if frame != nil {
		currentThread.Backtrace = append(currentThread.Backtrace, *frame)
	    }
	}
    }

    if currentThread != nil {
	// Don't forget to process the last thread.
	currentThread.Name = determineThreadRole(currentThread.Backtrace)
	threads = append(threads, *currentThread)
    }

    // Ensure we don't have duplicate threads.
    return deduplicateThreads(threads)
}

// getThreadSummary provides a brief summary of thread activities.
// Parameters:
// - threads: A slice of ThreadInfo objects representing threads.
// Returns:
// - A map summarizing thread activities by role or top function.
func getThreadSummary(threads []ThreadInfo) map[string]int {
    summary := make(map[string]int)
    for _, thread := range threads {
	if thread.Name != "Unknown" {
	    summary[thread.Name]++
	} else {
	    // Try to categorize unknown threads by their top function.
	    if len(thread.Backtrace) > 0 {
		topFunc := thread.Backtrace[0].Function
		if !isSystemFunction(topFunc) {
		    summary[fmt.Sprintf("Unknown (%s)", topFunc)]++
		}
	    }
	}
    }
    return summary
}
