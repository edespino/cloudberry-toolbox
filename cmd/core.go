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

// File: cmd/core.go
// Implements the `core` command for analyzing PostgreSQL core dumps.
// Purpose: This file implements the core analysis functionality for PostgreSQL core dumps in Apache Cloudberry (Incubating).
// It defines the `core` command, which analyzes core dumps to extract stack traces, thread information, signal details, and
// shared library mappings. Additionally, it supports comparing multiple core files to identify common crash patterns.
// Dependencies: Utilizes the Cobra library for CLI command handling and standard libraries for file management.

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/spf13/cobra"
)

// Global variables for CLI flags
var (
	outputDir   string // Directory to store analysis results
	maxCores    int
	compareFlag bool
)

// coreCmd represents the core analysis command
var coreCmd = &cobra.Command{
	Use:   "core [core_file_or_directory]",
	Short: "Analyze PostgreSQL core files",
	Long: `Analyze PostgreSQL core files from Apache Cloudberry (Incubating).
This tool provides detailed analysis of core dumps including stack traces,
thread information, signal analysis, and shared library information.

It can analyze a single core file or multiple core files in a directory:
  cbtoolbox core /path/to/core.1234
  cbtoolbox core /var/lib/postgres/cores/ --max-cores=5

Features:
- Stack trace analysis
- Thread inspection
- Register state examination
- Signal information
- Shared library mapping
- Core file comparison for pattern detection`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("please specify a core file or directory")
		}
		return runCoreAnalysis(args[0])
	},
}

func init() {
	rootCmd.AddCommand(coreCmd)
	coreCmd.Flags().StringVar(&outputDir, "output-dir", "/var/log/postgres_cores", "Directory to store analysis results")
	coreCmd.Flags().IntVar(&maxCores, "max-cores", 0, "Maximum number of core files to analyze")
	coreCmd.Flags().BoolVar(&compareFlag, "compare", false, "Compare core files and identify patterns")
}

// runCoreAnalysis is the main entry point for core file analysis
// Validates inputs, processes core files, and optionally compares results.
// runCoreAnalysis validates input, analyzes core files, and optionally compares results.
func runCoreAnalysis(path string) error {
    if err := validateFormat(formatFlag); err != nil {
        return err
    }

    if err := os.MkdirAll(outputDir, 0755); err != nil {
        return fmt.Errorf("failed to create output directory: %w", err)
    }

    // Find PostgreSQL binary
    gphome := os.Getenv("GPHOME")
    if gphome == "" {
        return fmt.Errorf("GPHOME environment variable must be set")
    }

    // Find core files
    coreFiles, err := findCoreFiles(path)
    if err != nil {
        return err
    }

    if len(coreFiles) == 0 {
        return fmt.Errorf("no core files found in %s", path)
    }

    if maxCores > 0 && len(coreFiles) > maxCores {
        fmt.Printf("Limiting analysis to %d most recent core files\n", maxCores)
        coreFiles = coreFiles[:maxCores]
    }

    var analyses []CoreAnalysis
    var mu sync.Mutex
    var wg sync.WaitGroup

    // Process each core file
    for _, coreFile := range coreFiles {
        wg.Add(1)
        go func(cf string) {
            defer wg.Done()
            analysis, err := analyzeCoreFile(cf, gphome)
            if err != nil {
                fmt.Printf("Error analyzing %s: %v\n", cf, err)
                return
            }

            // Incorporate basic_info dynamically into analysis
            basicInfo := parseBasicInfo(analysis.FileInfo.FileOutput)
            analysis.BasicInfo = basicInfo

            mu.Lock()
            analyses = append(analyses, analysis)
            mu.Unlock()

            // Use new saveOrPrintAnalysis function
            if err := saveOrPrintAnalysis(analysis); err != nil {
                fmt.Printf("Error outputting analysis for %s: %v\n", cf, err)
            }
        }(coreFile)
    }

    wg.Wait()

    if len(analyses) == 0 {
        return fmt.Errorf("no core files were analyzed successfully")
    }

    // Compare core files if requested
    if compareFlag && len(analyses) > 1 {
        comparison := compareCores(analyses)
        if err := saveComparison(comparison); err != nil {
            fmt.Printf("Error saving comparison results: %v\n", err)
        }
    }

    return nil
}

// findCoreFiles locates core files in the specified path
// Supports multiple filename patterns for flexibility.
// findCoreFiles locates core files matching known patterns in the given path.
func findCoreFiles(path string) ([]string, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !fileInfo.IsDir() {
		return []string{path}, nil
	}

	var coreFiles []string
	patterns := []string{
		"core.*",
		"*.core",
		"core",
		"core-*",
		"**/core-*-*-*-*-*",
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(path, pattern))
		if err != nil {
			continue
		}
		coreFiles = append(coreFiles, matches...)
	}

	return coreFiles, nil
}
