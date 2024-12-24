// File: cmd/core_parser_signal.go

package cmd

import (
    "fmt"
    "strconv"
    "strings"
    "regexp"
)

// signalMap provides names for common signals
var signalMap = map[int]string{
    1:  "SIGHUP",   // Hangup
    2:  "SIGINT",   // Terminal interrupt
    3:  "SIGQUIT",  // Terminal quit
    4:  "SIGILL",   // Illegal instruction
    6:  "SIGABRT",  // Process abort
    7:  "SIGBUS",   // Bus error
    8:  "SIGFPE",   // Floating point exception
    9:  "SIGKILL",  // Kill process
    11: "SIGSEGV",  // Segmentation violation
    13: "SIGPIPE",  // Broken pipe
    14: "SIGALRM",  // Timer signal
    15: "SIGTERM",  // Termination
}

// signalCodeMap maps signal-specific codes to descriptions
var signalCodeMap = map[int]map[int]string{
    11: { // SIGSEGV codes
	1: "SEGV_MAPERR (Address not mapped to object)",
	2: "SEGV_ACCERR (Invalid permissions for mapped object)",
	3: "SEGV_BNDERR (Failed address bound checks)",
	4: "SEGV_PKUERR (Access was denied by memory protection keys)",
    },
    7: { // SIGBUS codes
	1: "BUS_ADRALN (Invalid address alignment)",
	2: "BUS_ADRERR (Nonexistent physical address)",
	3: "BUS_OBJERR (Object-specific hardware error)",
    },
    8: { // SIGFPE codes
	1: "FPE_INTDIV (Integer divide by zero)",
	2: "FPE_INTOVF (Integer overflow)",
	3: "FPE_FLTDIV (Floating point divide by zero)",
	4: "FPE_FLTOVF (Floating point overflow)",
	5: "FPE_FLTUND (Floating point underflow)",
	6: "FPE_FLTRES (Floating point inexact result)",
	7: "FPE_FLTINV (Invalid floating point operation)",
	8: "FPE_FLTSUB (Subscript out of range)",
    },
}

// parseSignalInfo extracts signal information from GDB output
func parseSignalInfo(output string) SignalInfo {
    info := SignalInfo{}

    // Look for direct signal info
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
    if name, ok := signalMap[signo]; ok {
	return name
    }
    return fmt.Sprintf("SIGNAL_%d", signo)
}

// getSignalDescription provides detailed signal description
func getSignalDescription(signo, code int) string {
    var desc strings.Builder

    // Get basic signal description
    switch signo {
    case 11: // SIGSEGV
	desc.WriteString("Segmentation fault")
    case 6: // SIGABRT
	desc.WriteString("Process abort signal (possibly assertion failure)")
    case 7: // SIGBUS
	desc.WriteString("Bus error")
    case 8: // SIGFPE
	desc.WriteString("Floating point exception")
    default:
	desc.WriteString(fmt.Sprintf("Signal %d", signo))
    }

    // Add specific code description if available
    if codes, ok := signalCodeMap[signo]; ok {
	if codeDesc, ok := codes[code]; ok {
	    desc.WriteString(fmt.Sprintf(" - %s", codeDesc))
	} else if code != 0 {
	    desc.WriteString(fmt.Sprintf(" (code %d)", code))
	}
    }

    return desc.String()
}

// enhanceSignalInfo adds context to signal information
func enhanceSignalInfo(info *SignalInfo, analysis *CoreAnalysis) {
    // Try to detect signal from crash handler if not already set
    if info.SignalNumber == 0 {
	for _, frame := range analysis.StackTrace {
	    switch {
	    case strings.Contains(frame.Function, "SigillSigsegvSigbus"):
		info.SignalNumber = 11 // SIGSEGV
		info.SignalName = "SIGSEGV"
		info.SignalDescription = "Segmentation fault"
	    case strings.Contains(frame.Function, "AbortHandler"):
		info.SignalNumber = 6 // SIGABRT
		info.SignalName = "SIGABRT"
		info.SignalDescription = "Process abort"
	    }
	}
    }

    // Add context about where crash occurred
    for _, thread := range analysis.Threads {
	if thread.IsCrashed {
	    if keyFunc := findKeyFunction(thread.Backtrace); keyFunc != "" {
		if !strings.Contains(info.SignalDescription, keyFunc) {
		    info.SignalDescription += fmt.Sprintf(" in %s", keyFunc)
		}
	    }
	    break
	}
    }

    // Add fault address context if available
    if info.FaultAddress != "" {
	addFaultAddressContext(info, analysis)
    }

    // Add CloudBerry-specific context
    addCloudBerryContext(info, analysis)
}

// addFaultAddressContext adds information about the fault address
func addFaultAddressContext(info *SignalInfo, analysis *CoreAnalysis) {
    addr, err := strconv.ParseUint(strings.TrimPrefix(info.FaultAddress, "0x"), 16, 64)
    if err != nil {
	return
    }

    // Check if address is in any mapped library
    for _, lib := range analysis.Libraries {
	start, _ := strconv.ParseUint(strings.TrimPrefix(lib.TextStart, "0x"), 16, 64)
	end, _ := strconv.ParseUint(strings.TrimPrefix(lib.TextEnd, "0x"), 16, 64)
	if addr >= start && addr <= end {
	    info.SignalDescription += fmt.Sprintf(" (fault address in %s)", lib.Name)
	    return
	}
    }

    // If not in any library, might be stack/heap
    if info.SignalDescription != "" {
	info.SignalDescription += " (fault address not in mapped memory)"
    }
}

// addCloudBerryContext adds CloudBerry-specific crash context
func addCloudBerryContext(info *SignalInfo, analysis *CoreAnalysis) {
    // Look for common CloudBerry crash patterns
    for _, thread := range analysis.Threads {
	if !thread.IsCrashed {
	    continue
	}

	for _, frame := range thread.Backtrace {
	    switch {
	    case strings.Contains(frame.Function, "rxThreadFunc"):
		info.SignalDescription += "\nCrash occurred in interconnect receive thread"
	    case strings.Contains(frame.Function, "MotionLayerEntry"):
		info.SignalDescription += "\nCrash occurred in motion layer"
	    case strings.Contains(frame.Function, "execMain"):
		info.SignalDescription += "\nCrash occurred in query executor"
	    }
	}
    }

    // Add information about query if available
    if cmdline, ok := analysis.BasicInfo["cmdline"]; ok {
	if strings.Contains(cmdline, "seg") {
	    info.SignalDescription += fmt.Sprintf("\nProcess was a segment worker: %s", cmdline)
	}
    }
}
