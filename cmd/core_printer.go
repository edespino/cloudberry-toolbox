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

// File: cmd/core_printer.go
// Purpose: Provides utilities for printing and summarizing core analysis results.
// Includes functions to format analysis output in a GDB-like style, print thread details,
// summarize key registers, shared libraries, and process information.
// Dependencies: Utilizes Go's standard libraries for formatting, date-time handling, and path operations.

package cmd

import (
    "fmt"
    "text/tabwriter"
    "os"
    "time"
    "path/filepath"
)

var gdbStyleOutput bool

// Initialize flags for GDB-style output.
func init() {
    coreCmd.Flags().BoolVar(&gdbStyleOutput, "gdb-style", false, "Output in GDB-like format")
}

// saveOrPrintAnalysis handles output based on the specified format.
// Parameters:
// - analysis: The CoreAnalysis object containing analysis data.
// Returns:
// - An error if the operation fails, or nil on success.
func saveOrPrintAnalysis(analysis CoreAnalysis) error {
    if gdbStyleOutput {
        return printGDBStyle(analysis)
    }

    // Proceed to save analysis when --gdb-style is not set
    err := saveAnalysis(analysis)
    if err != nil {
        fmt.Printf("[ERROR] Failed to save analysis: %v\n", err)
    }
    return err
}

// printGDBStyle outputs the analysis in a GDB-like format.
// Parameters:
// - analysis: The CoreAnalysis object containing analysis data.
// Returns:
// - An error if printing fails, or nil on success.
func printGDBStyle(analysis CoreAnalysis) error {
    fmt.Println("Cloudberry Database Core Analysis")
    fmt.Println("================================")
    if desc, ok := analysis.BasicInfo["description"]; ok {
        fmt.Printf("Process: %s\n", desc)
    }
    fmt.Printf("Core: %s\n", analysis.CoreFile)
    fmt.Printf("Time: %s\n", analysis.Timestamp)
    fmt.Printf("PostgreSQL: %s\n", analysis.PostgresInfo.Version)
    fmt.Printf("Cloudberry: %s\n", analysis.PostgresInfo.GPVersion)

    fmt.Printf("\nSignal Configuration:\n")
    fmt.Printf("%-10s  Stop    Print   Pass    Description\n", "Signal")
    fmt.Printf("%-10s  %-7s %-7s %-7s %s\n", 
        analysis.SignalInfo.SignalName,
        "Yes",  // Typically "Yes" for core dumps
        "Yes", 
        "Yes",
        analysis.SignalInfo.SignalDescription)

    fmt.Printf("\nProgram received signal %s (%d), %s\n",
        analysis.SignalInfo.SignalName,
        analysis.SignalInfo.SignalNumber,
        analysis.SignalInfo.SignalDescription)
    
    if analysis.SignalInfo.FaultInfo != nil {
        fmt.Printf("Fault address: %s\n", analysis.SignalInfo.FaultInfo.Address)
    }

    fmt.Println("\nThread Information:")
    for _, thread := range analysis.Threads {
        printThreadWithLWP(thread, thread.IsCrashed)
        fmt.Println()
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

// printThreadWithLWP prints thread details along with LWP (Light Weight Process) information.
// Parameters:
// - thread: The ThreadInfo object containing thread details.
// - crashed: Boolean indicating if the thread has crashed.
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

// printFrameDetailed outputs detailed information about a stack frame.
// Parameters:
// - frame: The StackFrame object representing a single stack frame.
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

// printRegistersEnhanced organizes and prints CPU register values.
// Parameters:
// - registers: A map containing register names and their corresponding values.

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

// printCrashHeader outputs a high-level summary of the crash.
// Parameters:
// - analysis: The CoreAnalysis object containing crash data.
func printCrashHeader(analysis CoreAnalysis) {
    fmt.Println("Cloudberry Database Core Dump Analysis")
    fmt.Println("======================================")
    fmt.Printf("Core file: %s\n", analysis.CoreFile)
    if t, err := time.Parse(time.RFC3339, analysis.Timestamp); err == nil {
        fmt.Printf("Time: %s\n", t.Format("Mon Jan 2 15:04:05 2006"))
    }
    fmt.Printf("PostgreSQL: %s\n", analysis.PostgresInfo.Version)
    fmt.Printf("Cloudberry: %s\n", analysis.PostgresInfo.GPVersion)
}

// printProcessInfo outputs process-level information from the analysis.
// Parameters:
// - analysis: The CoreAnalysis object containing process data.
func printProcessInfo(analysis CoreAnalysis) {
    fmt.Println("Process Information")
    fmt.Println("-------------------")
    if desc, ok := analysis.BasicInfo["description"] ; ok {
        fmt.Printf("Process: %s\n", desc)
    }
    if dbid, ok := analysis.BasicInfo["database_id"] ; ok {
        fmt.Printf("Database ID: %s\n", dbid)
    }
    if segid, ok := analysis.BasicInfo["segment_id"] ; ok {
        fmt.Printf("Segment ID: %s\n", segid)
    }
}

// printSignalInfo outputs signal-related details.
// Parameters:
// - analysis: The CoreAnalysis object containing signal data.
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

// printThreads outputs all thread information.
// Parameters:
// - analysis: The CoreAnalysis object containing thread details.
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

// printThread outputs details for a single thread.
// Parameters:
// - thread: The ThreadInfo object containing thread details.
// - crashed: Boolean indicating if the thread has crashed.
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

// printFrame outputs detailed stack frame information.
// Parameters:
// - frame: The StackFrame object containing frame details.
func printFrame(frame StackFrame) {
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

// printRegisters outputs register states.
// Parameters:
// - analysis: The CoreAnalysis object containing register details.
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

// printLibrarySummary outputs a summary of shared libraries.
// Parameters:
// - analysis: The CoreAnalysis object containing library information.
func printLibrarySummary(analysis CoreAnalysis) {
    fmt.Println("Shared Library Summary")
    fmt.Println("---------------------")
    
    // Group libraries by type
    typeGroups := make(map[string][]LibraryInfo)
    for _, lib := range analysis.Libraries {
        typeGroups[lib.Type] = append(typeGroups[lib.Type], lib)
    }
    
    // Print Cloudberry libraries first
    printLibraryGroup("Cloudberry Core", typeGroups["Core"])
    printLibraryGroup("Cloudberry Extensions", typeGroups["Extension"])
    
    // Print other important groups
    printLibraryGroup("Security Libraries", typeGroups["Security"])
    printLibraryGroup("Runtime Libraries", typeGroups["Runtime"])
    
    // Print unloaded libraries section
    var unloaded []LibraryInfo
    for _, lib := range analysis.Libraries {
        if !lib.IsLoaded {
            unloaded = append(unloaded, lib)
        }
    }
    if len(unloaded) > 0 {
        fmt.Println("\nUnloaded Libraries:")
        for _, lib := range unloaded {
            fmt.Printf("  %s\n", filepath.Base(lib.Name))
        }
    }
    
    // Print summary counts
    fmt.Println("\nLibrary Statistics:")
    for libType, libs := range typeGroups {
        fmt.Printf("  %s: %d libraries\n", libType, len(libs))
    }
}

// printLibraryGroup outputs details for a group of libraries.
// Parameters:
// - title: A string title for the library group.
// - libs: A slice of LibraryInfo objects representing the libraries.
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
