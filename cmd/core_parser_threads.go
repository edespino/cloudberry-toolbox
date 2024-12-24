// File: cmd/core_parser_threads.go

package cmd

import (
    "fmt"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"
)

// threadPatterns defines known PostgreSQL/CloudBerry thread patterns
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
    `(?i)fts`:            "FTS Probe",
    `(?i)ftsprobe`:       "FTS Probe",
    `(?i)rg_worker`:      "Resource Group Worker",
    `(?i)seqserver`:      "Sequence Server",
    `(?i)motionlauncher`:  "Motion Launcher",
    `(?i)resgroup`:       "Resource Group",
    `(?i)backendmain`:    "Backend Worker",
    `(?i)startup`:        "Startup Process",
    `(?i)logger`:         "Logger Process",
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

	    currentThread = &ThreadInfo{
		ThreadID:   matches[1],
		LWPID:      matches[2],
		State:      matches[3],
		IsCrashed:  strings.Contains(line, "* "), // GDB marks crashed thread with asterisk
	    }
	} else if currentThread != nil && strings.HasPrefix(line, "#") {
	    frame := parseStackFrame(line)
	    if frame != nil {
		currentThread.Backtrace = append(currentThread.Backtrace, *frame)
	    }
	}
    }

    if currentThread != nil {
	threads = append(threads, *currentThread)
    }

    // Post-process threads
    for i := range threads {
	threads[i] = enhanceThreadInfo(threads[i])
    }

    return deduplicateThreads(threads)
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

	// Extract source file and line number
	if srcMatch := regexp.MustCompile(`at ([^:]+):(\d+)`).FindStringSubmatch(line); srcMatch != nil {
	    frame.SourceFile = srcMatch[1]
	    frame.LineNumber, _ = strconv.Atoi(srcMatch[2])
	}

	// Extract module name
	if modMatch := regexp.MustCompile(`from ([^)]+)`).FindStringSubmatch(line); modMatch != nil {
	    frame.Module = filepath.Base(modMatch[1])
	}

	// Parse local variables if available
	if localsMatch := regexp.MustCompile(`locals = {([^}]+)}`).FindStringSubmatch(line); localsMatch != nil {
	    frame.Locals = parseLocals(localsMatch[1])
	}

	return frame
    }
    return nil
}

// enhanceThreadInfo adds additional context to thread information
func enhanceThreadInfo(thread ThreadInfo) ThreadInfo {
    // Determine thread role from backtrace
    thread.Name = determineThreadRole(thread.Backtrace)

    // Add context about crashed state
    if thread.IsCrashed {
	thread.State = fmt.Sprintf("%s (Crashed)", thread.State)
    }

    // Add query context if available
    for _, frame := range thread.Backtrace {
	if queryInfo, ok := frame.Locals["queryDesc"]; ok {
	    thread.Name = fmt.Sprintf("%s (Query: %s)", thread.Name, queryInfo)
	    break
	}
    }

    return thread
}

// determineThreadRole identifies thread role from backtrace
func determineThreadRole(backtrace []StackFrame) string {
    // First check backtrace functions
    callStack := parseCallStack(backtrace)
    for _, funcName := range callStack {
	for pattern, role := range threadPatterns {
	    if matched, _ := regexp.MatchString(pattern, funcName); matched {
		return role
	    }
	}
    }

    // Analyze thread characteristics
    if len(backtrace) > 0 {
	switch {
	case containsAny(backtrace[0].Function, []string{"exec", "dispatch"}):
	    return "Query Dispatcher"
	case containsAny(backtrace[0].Function, []string{"poll", "epoll"}):
	    return "Network Poller"
	case strings.Contains(backtrace[0].Function, "StandardHandlerForSigillSigsegvSigbus"):
	    return "Crashed Thread"
	}
    }

    return "Unknown"
}

// getThreadSummary provides a brief summary of thread activities
func getThreadSummary(threads []ThreadInfo) map[string]int {
    summary := make(map[string]int)
    for _, thread := range threads {
	if thread.Name != "Unknown" {
	    summary[thread.Name]++
	} else {
	    // Try to categorize unknown threads by their top function
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
