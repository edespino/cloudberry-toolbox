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

// File: cmd/core_parser_libraries.go
// Purpose: Provides utilities for parsing and analyzing shared library information
// from GDB output. Includes categorization of libraries, extraction of version
// information, and summary generation for shared libraries loaded in CloudBerry.
// Dependencies: Relies on Go's standard libraries for regex and string manipulation.

package cmd

import (
    "regexp"
    "strings"
    "path/filepath"
)

// LibraryCategory defines types of shared libraries.
type LibraryCategory struct {
    Type        string // The category type, e.g., "Core", "System".
    Description string // A human-readable description of the category.
    Pattern     string // A regex pattern to identify libraries in this category.
}

// libraryCategories defines known library categories.
var libraryCategories = []LibraryCategory{
    {
	Type:        "Core",
	Description: "CloudBerry Core Libraries",
	Pattern:     `libpostgres\.so`,
    },
    {
	Type:        "Extension",
	Description: "CloudBerry Extensions",
	Pattern:     `/postgresql/.*\.so`,
    },
    {
	Type:        "Interconnect",
	Description: "CloudBerry Interconnect",
	Pattern:     `interconnect\.so`,
    },
    {
	Type:        "Compression",
	Description: "Compression Libraries",
	Pattern:     `(zlib|lz4|zstd|bzip2)`,
    },
    {
	Type:        "Security",
	Description: "Security Libraries",
	Pattern:     `(ssl|crypto|pam|krb5|gssapi|ldap|sasl)`,
    },
    {
	Type:        "System",
	Description: "System Libraries",
	Pattern:     `^/lib`,
    },
    {
	Type:        "Runtime",
	Description: "Language Runtime",
	Pattern:     `(libc|libstdc\+\+|libgcc)`,
    },
}

// parseSharedLibraries extracts shared library information from GDB output.
// Parameters:
// - output: The raw GDB output containing library mappings.
// Returns:
// - A slice of LibraryInfo objects with details about each library.
func parseSharedLibraries(output string) []LibraryInfo {
    var libraries []LibraryInfo
    libraryRE := regexp.MustCompile(`(?m)^(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\w+)\s+(.+?\.so[.0-9]*)`)

    for _, line := range strings.Split(output, "\n") {
	if matches := libraryRE.FindStringSubmatch(line); matches != nil {
	    startAddr := matches[1]
	    endAddr := matches[2]
	    loadStatus := matches[3]
	    libPath := matches[4]

	    library := LibraryInfo{
		Name:      strings.TrimSpace(libPath),
		StartAddr: startAddr,
		EndAddr:   endAddr,
		Version:   getLibraryVersion(libPath),
		Type:      categorizeLibrary(libPath),
		IsLoaded:  loadStatus == "Yes",
		TextStart: startAddr,
		TextEnd:   endAddr,
	    }

	    libraries = append(libraries, library)
	}
    }

    return libraries
}

// categorizeLibrary determines the type of shared library.
// Parameters:
// - path: The file path of the library.
// Returns:
// - A string representing the library category type.
func categorizeLibrary(path string) string {
    for _, category := range libraryCategories {
	if matched, _ := regexp.MatchString(category.Pattern, path); matched {
	    return category.Type
	}
    }
    return "Other"
}

// getLibraryVersion attempts to extract version information from a library's name.
// Parameters:
// - libPath: The file path of the library.
// Returns:
// - A string representing the library version, if found; otherwise, an empty string.
func getLibraryVersion(libPath string) string {
    verMatch := regexp.MustCompile(`\.so[.]([0-9.]+)$`).FindStringSubmatch(libPath)
    if verMatch != nil {
	return verMatch[1]
    }

    parts := strings.Split(filepath.Base(libPath), "-")
    for _, part := range parts {
	if regexp.MustCompile(`^[0-9.]+$`).MatchString(part) {
	    return part
	}
    }

    return ""
}

// analyzeLibraries provides analysis of loaded libraries.
// Parameters:
// - libraries: A slice of LibraryInfo objects.
// Returns:
// - A map containing analysis details, such as counts by category and unloaded libraries.
func analyzeLibraries(libraries []LibraryInfo) map[string]interface{} {
    analysis := make(map[string]interface{})

    categoryCounts := make(map[string]int)
    for _, lib := range libraries {
	categoryCounts[lib.Type]++
    }
    analysis["category_counts"] = categoryCounts

    var unloaded []string
    for _, lib := range libraries {
	if !lib.IsLoaded {
	    unloaded = append(unloaded, lib.Name)
	}
    }
    if len(unloaded) > 0 {
	analysis["unloaded_libraries"] = unloaded
    }

    cloudberryComponents := make(map[string][]string)
    for _, lib := range libraries {
	if lib.Type == "Core" || lib.Type == "Extension" {
	    component := filepath.Base(filepath.Dir(lib.Name))
	    cloudberryComponents[component] = append(
		cloudberryComponents[component],
		filepath.Base(lib.Name),
	    )
	}
    }
    analysis["cloudberry_components"] = cloudberryComponents

    return analysis
}

// findAddressLibrary determines which library contains a given memory address.
// Parameters:
// - address: The memory address to locate.
// - libraries: A slice of LibraryInfo objects.
// Returns:
// - A pointer to the LibraryInfo containing the address, or nil if not found.
func findAddressLibrary(address string, libraries []LibraryInfo) *LibraryInfo {
    if !strings.HasPrefix(address, "0x") {
	address = "0x" + address
    }

    addr := strings.ToLower(address)
    for _, lib := range libraries {
	start := strings.ToLower(lib.TextStart)
	end := strings.ToLower(lib.TextEnd)

	if addr >= start && addr <= end {
	    return &lib
	}
    }

    return nil
}

// getLibrarySummary provides a human-readable summary of libraries.
// Parameters:
// - libraries: A slice of LibraryInfo objects.
// Returns:
// - A string summarizing the library categories and any unloaded libraries.
func getLibrarySummary(libraries []LibraryInfo) string {
    var summary strings.Builder

    // Count by category
    counts := make(map[string]int)
    for _, lib := range libraries {
	counts[lib.Type]++
    }

    summary.WriteString("Library Summary:\n")
    for _, category := range libraryCategories {
	if count := counts[category.Type]; count > 0 {
	    summary.WriteString(
		strings.Repeat(" ", 2) +
		category.Description +
		": " +
		strings.Repeat(".", 20) +
		" " +
		strings.Repeat(" ", 3-len(string(count))) +
		string(count) + "\n",
	    )
	}
    }

    // Report unloaded libraries
    var unloaded []string
    for _, lib := range libraries {
	if !lib.IsLoaded {
	    unloaded = append(unloaded, filepath.Base(lib.Name))
	}
    }
    if len(unloaded) > 0 {
	summary.WriteString("\nUnloaded Libraries:\n")
	for _, lib := range unloaded {
	    summary.WriteString(strings.Repeat(" ", 2) + lib + "\n")
	}
    }

    return summary.String()
}
