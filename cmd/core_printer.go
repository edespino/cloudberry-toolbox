// File: cmd/core_printer.go

package cmd

import (
    "fmt"
    "text/tabwriter"
    "os"
    "time"
    "path/filepath"
)

var gdbStyleOutput bool

// Initialize flags
func init() {
    coreCmd.Flags().BoolVar(&gdbStyleOutput, "gdb-style", false, "Output in GDB-like format")
}

// saveOrPrintAnalysis handles output based on format flag
func saveOrPrintAnalysis(analysis CoreAnalysis) error {
    if gdbStyleOutput {
        return printGDBStyle(analysis)
    }
    return saveAnalysis(analysis)
}

// printGDBStyle outputs the analysis in a GDB-like format
// In core_printer.go:

func printGDBStyle(analysis CoreAnalysis) error {
    fmt.Println("CloudBerry Database Core Analysis")
    fmt.Println("================================")
    if desc, ok := analysis.BasicInfo["description"]; ok {
        fmt.Printf("Process: %s\n", desc)
    }
    fmt.Printf("Core: %s\n", analysis.CoreFile)
    fmt.Printf("Time: %s\n", analysis.Timestamp)
    fmt.Printf("PostgreSQL: %s\n", analysis.PostgresInfo.Version)
    fmt.Printf("CloudBerry: %s\n", analysis.PostgresInfo.GPVersion)

    // Signal Configuration
    fmt.Printf("\nSignal Configuration:\n")
    fmt.Printf("%-10s  Stop    Print   Pass    Description\n", "Signal")
    fmt.Printf("%-10s  %-7s %-7s %-7s %s\n", 
        analysis.SignalInfo.SignalName,
        "Yes",  // These are typically Yes for core dumps
        "Yes", 
        "Yes",
        "Segmentation fault")

    fmt.Printf("\nProgram received signal %s (%d), %s\n",
        analysis.SignalInfo.SignalName,
        analysis.SignalInfo.SignalNumber,
        analysis.SignalInfo.SignalDescription)
    
    if analysis.SignalInfo.FaultInfo != nil {
        fmt.Printf("Fault address: %s\n", analysis.SignalInfo.FaultInfo.Address)
    }

    fmt.Println("\nThread Information:")
    // Print crashed thread first
    for _, thread := range analysis.Threads {
        if thread.IsCrashed {
            printThreadWithLWP(thread, true)
            fmt.Println()
        }
    }
    // Print other threads
    for _, thread := range analysis.Threads {
        if !thread.IsCrashed {
            printThreadWithLWP(thread, false)
            fmt.Println()
        }
    }

    fmt.Println("Registers:")
    printRegistersEnhanced(analysis.Registers)

    fmt.Println("\nKey Shared Libraries:")
    for _, lib := range analysis.Libraries {
        if lib.Type == "Core" || lib.Type == "Extension" {
            fmt.Printf("  %s [%s-%s]\n", 
                filepath.Base(lib.Name),
                lib.StartAddr,
                lib.EndAddr)
        }
    }

    return nil
}

func printThreadWithLWP(thread ThreadInfo, crashed bool) {
    threadHeader := fmt.Sprintf("Thread %s", thread.ThreadID)
    if thread.LWPID != "" {
        threadHeader += fmt.Sprintf(" [LWP %s]", thread.LWPID)
    }
    if thread.Name != "" {
        threadHeader += fmt.Sprintf(" (%s)", thread.Name)
    }
    if crashed {
        threadHeader += " (Crashed)"
    }
    fmt.Printf("%s:\n", threadHeader)
    
    for _, frame := range thread.Backtrace {
        printFrameDetailed(frame)
    }
}

func boolToYesNo(b bool) string {
    if b {
        return "Yes"
    }
    return "No"
}

func printFrameDetailed(frame StackFrame) {
    frameStr := fmt.Sprintf("#%s  %s in %s", 
        frame.FrameNum,
        frame.Location,
        frame.Function)
    
    if frame.Module != "" {
        frameStr += fmt.Sprintf(" from %s", frame.Module)
    }
    
    fmt.Println(frameStr)
}

func printRegistersEnhanced(registers map[string]string) {
    // Group registers logically
    regGroups := [][]string{
        {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"},
        {"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"},
        {"rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"},
    }

    for _, group := range regGroups {
        for _, reg := range group {
            if val, ok := registers[reg]; ok {
                fmt.Printf("%-8s %s\n", reg+":", val)
            }
        }
        fmt.Println()
    }
}

func printLibrary(lib LibraryInfo) {
    fmt.Printf("  %s", filepath.Base(lib.Name))
    if lib.Version != "" {
        fmt.Printf(" (version %s)", lib.Version)
    }
    if lib.TextStart != "" && lib.TextEnd != "" {
        fmt.Printf(" [%s-%s]", lib.TextStart, lib.TextEnd)
    }
    fmt.Println()
}

func printCrashHeader(analysis CoreAnalysis) {
    fmt.Println("CloudBerry Database Core Dump Analysis")
    fmt.Println("======================================")
    fmt.Printf("Core file: %s\n", analysis.CoreFile)
    if t, err := time.Parse(time.RFC3339, analysis.Timestamp); err == nil {
        fmt.Printf("Time: %s\n", t.Format("Mon Jan 2 15:04:05 2006"))
    }
    fmt.Printf("PostgreSQL: %s\n", analysis.PostgresInfo.Version)
    fmt.Printf("CloudBerry: %s\n", analysis.PostgresInfo.GPVersion)
}

func printProcessInfo(analysis CoreAnalysis) {
    fmt.Println("Process Information")
    fmt.Println("-------------------")
    if desc, ok := analysis.BasicInfo["description"]; ok {
        fmt.Printf("Process: %s\n", desc)
    }
    if dbid, ok := analysis.BasicInfo["database_id"]; ok {
        fmt.Printf("Database ID: %s\n", dbid)
    }
    if segid, ok := analysis.BasicInfo["segment_id"]; ok {
        fmt.Printf("Segment ID: %s\n", segid)
    }
}

func printSignalInfo(analysis CoreAnalysis) {
    fmt.Println("Signal Information")
    fmt.Println("-----------------")
    fmt.Printf("Program received signal %s (%d), %s\n",
        analysis.SignalInfo.SignalName,
        analysis.SignalInfo.SignalNumber,
        analysis.SignalInfo.SignalDescription)
    
    if analysis.SignalInfo.FaultAddress != "" {
        fmt.Printf("Fault address: %s\n", analysis.SignalInfo.FaultAddress)
    }
}

func printThreads(analysis CoreAnalysis) {
    fmt.Println("Thread Information")
    fmt.Println("-----------------")
    
    // Print crashed thread first
    for _, thread := range analysis.Threads {
        if thread.IsCrashed {
            printThread(thread, true)
            fmt.Println()
        }
    }
    
    // Print other threads
    for _, thread := range analysis.Threads {
        if !thread.IsCrashed {
            printThread(thread, false)
            fmt.Println()
        }
    }
}

func printThread(thread ThreadInfo, crashed bool) {
    threadHeader := fmt.Sprintf("Thread %s", thread.ThreadID)
    if thread.Name != "" {
        threadHeader += fmt.Sprintf(" (%s)", thread.Name)
    }
    if crashed {
        threadHeader += " (Crashed)"
    }
    fmt.Println(threadHeader)
    
    for _, frame := range thread.Backtrace {
        printFrame(frame)
    }
}

func printFrame(frame StackFrame) {
    // Format similar to GDB's stack frame output
    frameStr := fmt.Sprintf("#%s  %s in %s", 
        frame.FrameNum,
        frame.Location,
        frame.Function)
    
    if frame.Arguments != "" {
        frameStr += fmt.Sprintf(" (%s)", frame.Arguments)
    }
    
    if frame.Module != "" {
        frameStr += fmt.Sprintf(" from %s", frame.Module)
    }
    
    if frame.SourceFile != "" {
        frameStr += fmt.Sprintf(" at %s:%d", 
            frame.SourceFile, 
            frame.LineNumber)
    }
    
    fmt.Println(frameStr)
}

func printRegisters(analysis CoreAnalysis) {
    fmt.Println("Register State")
    fmt.Println("-------------")
    w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
    
    // Group registers logically
    generalPurpose := []string{"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"}
    extended := []string{"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
    special := []string{"rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"}
    
    // Print general purpose registers
    for _, reg := range generalPurpose {
        if val, ok := analysis.Registers[reg]; ok {
            fmt.Fprintf(w, "%s:\t%s\n", reg, val)
        }
    }
    fmt.Fprintln(w)
    
    // Print extended registers
    for _, reg := range extended {
        if val, ok := analysis.Registers[reg]; ok {
            fmt.Fprintf(w, "%s:\t%s\n", reg, val)
        }
    }
    fmt.Fprintln(w)
    
    // Print special registers
    for _, reg := range special {
        if val, ok := analysis.Registers[reg]; ok {
            fmt.Fprintf(w, "%s:\t%s\n", reg, val)
        }
    }
    w.Flush()
}

func printLibrarySummary(analysis CoreAnalysis) {
    fmt.Println("Shared Library Summary")
    fmt.Println("---------------------")
    
    // Group libraries by type
    typeGroups := make(map[string][]LibraryInfo)
    for _, lib := range analysis.Libraries {
        typeGroups[lib.Type] = append(typeGroups[lib.Type], lib)
    }
    
    // Print CloudBerry libraries first
    printLibraryGroup("CloudBerry Core", typeGroups["Core"])
    printLibraryGroup("CloudBerry Extensions", typeGroups["Extension"])
    
    // Print other important groups
    printLibraryGroup("Security Libraries", typeGroups["Security"])
    printLibraryGroup("Runtime Libraries", typeGroups["Runtime"])
    
    // Print summary counts
    fmt.Println("\nLibrary Statistics:")
    for libType, libs := range typeGroups {
        fmt.Printf("  %s: %d libraries\n", libType, len(libs))
    }
}

func printLibraryGroup(title string, libs []LibraryInfo) {
    if len(libs) == 0 {
        return
    }
    
    fmt.Printf("\n%s:\n", title)
    for _, lib := range libs {
        fmt.Printf("  %s", filepath.Base(lib.Name))
        if lib.Version != "" {
            fmt.Printf(" (version %s)", lib.Version)
        }
        fmt.Println()
    }
}
