// File: cmd/core_gdb.go
package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// analyzeCoreFile performs detailed analysis of a single core file
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

	return analysis, nil
}

// getPostgresInfo collects PostgreSQL binary information
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

// dirExists checks if directory exists
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// gdbAnalysis performs detailed analysis using GDB
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
		"info proc mappings",  // Add memory mappings
		"thread apply all print $_thread", // Get detailed thread info
		"print $_siginfo._sifields._sigfault", // Detailed fault info
		"info frame",  // Detailed frame info
		"info locals", // Local variables
		"bt full",     // Full backtrace with locals
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

// parseGDBOutput processes GDB output and updates the analysis structure
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
