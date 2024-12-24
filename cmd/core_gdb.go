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

// File: cmd/core_gdb.go
// Purpose: Implements functionality for analyzing PostgreSQL core files using GDB.
// This file defines the `analyzeCoreFile` function, which integrates with GDB to extract
// detailed information such as stack traces, threads, signal details, and shared library mappings.
// The data is structured into the `CoreAnalysis` object for further processing.
// Dependencies: Relies on external GDB commands and PostgreSQL/CloudBerry binaries.

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// analyzeCoreFile performs a comprehensive analysis of a core dump file.
// Parameters:
// - corePath: Path to the core dump file.
// - gphome: Path to the PostgreSQL/CloudBerry installation.
// Returns:
// - A `CoreAnalysis` object containing parsed details from the core dump.
// - An error if the analysis fails at any step.
func analyzeCoreFile(corePath string, gphome string) (CoreAnalysis, error) {
	analysis := CoreAnalysis{
		Timestamp: time.Now().Format(time.RFC3339),
		CoreFile:  corePath,
	}

	// Get basic file information
	fileInfo, err := os.Stat(corePath)
	if err != nil {
		return analysis, err
	}

	analysis.FileInfo = FileInfo{
		Size:    fileInfo.Size(),
		Created: fileInfo.ModTime().Format(time.RFC3339),
	}

	// Get file type information
	cmd := exec.Command("file", corePath)
	output, err := cmd.Output()
	if err != nil {
		return analysis, fmt.Errorf("failed to get file info: %w", err)
	}
	analysis.FileInfo.FileOutput = strings.TrimSpace(string(output))

	// Parse basic info BEFORE GDB analysis
	analysis.BasicInfo = parseBasicInfo(analysis.FileInfo.FileOutput)

	// Find PostgreSQL binary
	postgresPath := filepath.Join(gphome, "bin", "postgres")
	if _, err := os.Stat(postgresPath); err != nil {
		return analysis, fmt.Errorf("postgres binary not found at %s", postgresPath)
	}

	// Get PostgreSQL information
	pgInfo, err := getPostgresInfo(postgresPath)
	if err != nil {
		return analysis, err
	}
	analysis.PostgresInfo = pgInfo

	// Run GDB analysis
	if err := gdbAnalysis(&analysis, postgresPath); err != nil {
		return analysis, err
	}

	// Deduplicate stack trace
	analysis.StackTrace = deduplicateStackTrace(analysis.StackTrace)

	// Enhance signal info from stack
	detectSignalFromStack(&analysis)

	// Enhance basic info with thread and signal context
	enhanceProcessInfo(analysis.BasicInfo, &analysis)

	return analysis, nil
}

// deduplicateStackTrace removes duplicate stack frames from the analysis.
// Parameters:
// - frames: A slice of `StackFrame` objects representing the stack trace.
// Returns:
// - A deduplicated slice of `StackFrame` objects.
func deduplicateStackTrace(frames []StackFrame) []StackFrame {
	seen := make(map[string]bool)
	var result []StackFrame

	for _, frame := range frames {
		key := fmt.Sprintf("%s:%s:%s", frame.Function, frame.Location, frame.Module)
		if !seen[key] {
			seen[key] = true
			result = append(result, frame)
		}
	}

	return result
}

// getPostgresInfo collects PostgreSQL binary information such as version and build options.
// Parameters:
// - binaryPath: Path to the PostgreSQL binary.
// Returns:
// - A `PostgresInfo` object containing version and configuration details.
// - An error if the information cannot be retrieved.
func getPostgresInfo(binaryPath string) (PostgresInfo, error) {
	info := PostgresInfo{
		BinaryPath: binaryPath,
	}

	// Get PostgreSQL version
	cmd := exec.Command(binaryPath, "--version")
	output, err := cmd.Output()
	if err == nil {
		info.Version = strings.TrimSpace(string(output))
	}

	// Get CloudBerry version
	cmd = exec.Command(binaryPath, "--gp-version")
	output, err = cmd.Output()
	if err == nil {
		info.GPVersion = strings.TrimSpace(string(output))
	}

	// Get build options
	pgConfigPath := filepath.Join(filepath.Dir(binaryPath), "pg_config")
	cmd = exec.Command(pgConfigPath, "--configure")
	output, err = cmd.Output()
	if err == nil {
		// Clean up the configure options
		options := strings.Fields(strings.TrimSpace(string(output)))
		for i, opt := range options {
			opt = strings.Trim(opt, "'")
			options[i] = opt
		}
		info.BuildOptions = options
	}

	return info, nil
}

// dirExists checks if a directory exists at the specified path.
// Parameters:
// - path: The directory path to check.
// Returns:
// - True if the directory exists, false otherwise.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// gdbAnalysis performs detailed analysis using GDB commands.
// Parameters:
// - analysis: A pointer to the `CoreAnalysis` object to update with GDB results.
// - binaryPath: Path to the PostgreSQL binary.
// Returns:
// - An error if the GDB commands fail.
func gdbAnalysis(analysis *CoreAnalysis, binaryPath string) error {
  gdbCmds := []string{
      "set pagination off",
      "set print pretty on",
      "set print object on",
      "info threads",
      "thread apply all bt full",
      "info registers all",
      "info signal SIGABRT",
      "info signal SIGSEGV",
      "info signal SIGBUS",
      "print $_siginfo",
      "info sharedlibrary",
      "x/1i $pc",
      "info proc mappings",
      "thread apply all print $_thread",
      "print $_siginfo._sifields._sigfault",
      "info frame",
      "info locals",
      "bt full",
      "print $_siginfo.si_code",  // Add signal code information
      "maintenance info sections", // Add memory section information
      "quit",
  }

	// Add source directory info for better line numbers
	if srcDir := filepath.Join(filepath.Dir(binaryPath), "../src"); dirExists(srcDir) {
		gdbCmds = append([]string{"directory " + srcDir}, gdbCmds...)
	}

	args := []string{"-nx", "--batch"}
	for _, cmd := range gdbCmds {
		args = append(args, "-ex", cmd)
	}
	args = append(args, binaryPath, analysis.CoreFile)

	cmd := exec.Command("gdb", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("GDB analysis failed: %w", err)
	}

	// Parse GDB output
	parseGDBOutput(string(output), analysis)
	return nil
}

// parseGDBOutput processes GDB output and updates the analysis structure.
// Parameters:
// - output: The raw output from GDB.
// - analysis: A pointer to the `CoreAnalysis` object to update.
func parseGDBOutput(output string, analysis *CoreAnalysis) {
	// Parse stack trace
	analysis.StackTrace = parseStackTrace(output)

	// Parse threads
	analysis.Threads = parseThreads(output)

	// Parse registers
	analysis.Registers = parseRegisters(output)

	// Parse signal information
	analysis.SignalInfo = parseSignalInfo(output)

	// Parse shared libraries
	analysis.Libraries = parseSharedLibraries(output)
}
