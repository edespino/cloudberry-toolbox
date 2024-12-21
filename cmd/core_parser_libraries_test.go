// File: cmd/core_parser_libraries_test.go
package cmd

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseSharedLibraries(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []LibraryInfo
	}{
		{
			name: "single library",
			input: "0x00007ffff7dd7000 0x00007ffff7dd8000 Yes /usr/lib/libpostgres.so.5.1",
			expected: []LibraryInfo{
				{
					Name:      "/usr/lib/libpostgres.so.5.1",
					StartAddr: "0x00007ffff7dd7000",
					EndAddr:   "0x00007ffff7dd8000",
					Version:   "5.1",
					Type:      "Core",
					IsLoaded:  true,
					TextStart: "0x00007ffff7dd7000",
					TextEnd:   "0x00007ffff7dd8000",
				},
			},
		},
		{
			name: "multiple libraries",
			input: `0x00007ffff7dd7000 0x00007ffff7dd8000 Yes /usr/lib/libpostgres.so.5.1
0x00007ffff7bc4000 0x00007ffff7bc9000 Yes /usr/lib/postgresql/plpgsql.so
0x00007ffff79e4000 0x00007ffff79e9000 Yes /lib64/libcrypto.so.1.1`,
			expected: []LibraryInfo{
				{
					Name:      "/usr/lib/libpostgres.so.5.1",
					StartAddr: "0x00007ffff7dd7000",
					EndAddr:   "0x00007ffff7dd8000",
					Version:   "5.1",
					Type:      "Core",
					IsLoaded:  true,
					TextStart: "0x00007ffff7dd7000",
					TextEnd:   "0x00007ffff7dd8000",
				},
				{
					Name:      "/usr/lib/postgresql/plpgsql.so",
					StartAddr: "0x00007ffff7bc4000",
					EndAddr:   "0x00007ffff7bc9000",
					Type:      "Extension",
					IsLoaded:  true,
					TextStart: "0x00007ffff7bc4000",
					TextEnd:   "0x00007ffff7bc9000",
				},
				{
					Name:      "/lib64/libcrypto.so.1.1",
					StartAddr: "0x00007ffff79e4000",
					EndAddr:   "0x00007ffff79e9000",
					Version:   "1.1",
					Type:      "Security",
					IsLoaded:  true,
					TextStart: "0x00007ffff79e4000",
					TextEnd:   "0x00007ffff79e9000",
				},
			},
		},
		{
			name: "unloaded library",
			input: "0x00007ffff7dd7000 0x00007ffff7dd8000 No /usr/lib/libpostgres.so.5.1",
			expected: []LibraryInfo{
				{
					Name:      "/usr/lib/libpostgres.so.5.1",
					StartAddr: "0x00007ffff7dd7000",
					EndAddr:   "0x00007ffff7dd8000",
					Version:   "5.1",
					Type:      "Core",
					IsLoaded:  false,
					TextStart: "0x00007ffff7dd7000",
					TextEnd:   "0x00007ffff7dd8000",
				},
			},
		},
		{
			name: "empty input",
			input: "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSharedLibraries(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseSharedLibraries() =\n%+v\nwant:\n%+v", result, tt.expected)
			}
		})
	}
}

func TestCategorizeLibrary(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{"Core library", "/usr/lib/libpostgres.so", "Core"},
		{"Extension", "/usr/lib/postgresql/plpython3.so", "Extension"},
		{"Interconnect", "/usr/lib/interconnect.so", "Interconnect"},
		{"Compression lib", "/usr/lib/libzstd.so", "Compression"},
		{"Security lib", "/usr/lib/libssl.so", "Security"},
		{"System lib", "/lib/libc.so.6", "System"},
		{"Runtime lib", "/usr/lib/libstdc++.so.6", "Runtime"},
		{"Unknown lib", "/usr/lib/libunknown.so", "Other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := categorizeLibrary(tt.path)
			if result != tt.expected {
				t.Errorf("categorizeLibrary(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestGetLibraryVersion(t *testing.T) {
	tests := []struct {
		name     string
		libPath  string
		expected string
	}{
		{"Standard version format", "/usr/lib/libssl.so.1.1", "1.1"},
		{"Complex version", "/usr/lib/libcrypto.so.1.1.1f", "1.1.1f"},
		{"No version", "/usr/lib/libtest.so", ""},
		{"Version in filename", "libboost_system-mt-1.74.so", "1.74"},
		{"Multiple dots", "/usr/lib/libicudata.so.70.1", "70.1"},
		{"No .so extension", "/usr/lib/libtest", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getLibraryVersion(tt.libPath)
			if result != tt.expected {
				t.Errorf("getLibraryVersion(%q) = %q, want %q", tt.libPath, result, tt.expected)
			}
		})
	}
}

func TestAnalyzeLibraries(t *testing.T) {
	libraries := []LibraryInfo{
		{
			Name:     "/usr/lib/libpostgres.so.5.1",
			Type:     "Core",
			IsLoaded: true,
		},
		{
			Name:     "/usr/lib/postgresql/plpython3.so",
			Type:     "Extension",
			IsLoaded: true,
		},
		{
			Name:     "/usr/lib/libssl.so.1.1",
			Type:     "Security",
			IsLoaded: false,
		},
	}

	result := analyzeLibraries(libraries)

	// Check category counts
	categoryCounts, ok := result["category_counts"].(map[string]int)
	if !ok {
		t.Fatal("category_counts not found or wrong type")
	}
	if categoryCounts["Core"] != 1 {
		t.Errorf("Core category count = %d, want 1", categoryCounts["Core"])
	}
	if categoryCounts["Extension"] != 1 {
		t.Errorf("Extension category count = %d, want 1", categoryCounts["Extension"])
	}

	// Check unloaded libraries
	unloaded, ok := result["unloaded_libraries"].([]string)
	if !ok {
		t.Fatal("unloaded_libraries not found or wrong type")
	}
	if len(unloaded) != 1 || unloaded[0] != "/usr/lib/libssl.so.1.1" {
		t.Errorf("unloaded_libraries = %v, want [/usr/lib/libssl.so.1.1]", unloaded)
	}

	// Check Cloudberry components
	components, ok := result["cloudberry_components"].(map[string][]string)
	if !ok {
		t.Fatal("cloudberry_components not found or wrong type")
	}
	if len(components) == 0 {
		t.Error("cloudberry_components is empty")
	}
}

func TestFindAddressLibrary(t *testing.T) {
	libraries := []LibraryInfo{
		{
			Name:      "lib1.so",
			TextStart: "0x1000",
			TextEnd:   "0x2000",
		},
		{
			Name:      "lib2.so",
			TextStart: "0x3000",
			TextEnd:   "0x4000",
		},
	}

	tests := []struct {
		name        string
		address     string
		expectedLib string
	}{
		{"Address in first lib", "0x1500", "lib1.so"},
		{"Address in second lib", "0x3500", "lib2.so"},
		{"Address not in any lib", "0x5000", ""},
		{"Address with 0x prefix", "0x1500", "lib1.so"},
		{"Address without 0x prefix", "1500", "lib1.so"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findAddressLibrary(tt.address, libraries)
			if tt.expectedLib == "" {
				if result != nil {
					t.Errorf("findAddressLibrary(%q) = %v, want nil", tt.address, result)
				}
			} else {
				if result == nil || result.Name != tt.expectedLib {
					t.Errorf("findAddressLibrary(%q) = %v, want library with name %q", 
						tt.address, result, tt.expectedLib)
				}
			}
		})
	}
}

func TestGetLibrarySummary(t *testing.T) {
	libraries := []LibraryInfo{
		{
			Name:     "/usr/lib/libpostgres.so.5.1",
			Type:     "Core",
			IsLoaded: true,
		},
		{
			Name:     "/usr/lib/postgresql/plpython3.so",
			Type:     "Extension",
			IsLoaded: true,
		},
		{
			Name:     "/usr/lib/libssl.so.1.1",
			Type:     "Security",
			IsLoaded: false,
		},
	}

	summary := getLibrarySummary(libraries)

	// Check that summary contains key information
	if !strings.Contains(summary, "Library Summary:") {
		t.Error("Summary missing header")
	}
	if !strings.Contains(summary, "Cloudberry Core Libraries") {
		t.Error("Summary missing core libraries section")
	}
	if !strings.Contains(summary, "Unloaded Libraries:") {
		t.Error("Summary missing unloaded libraries section")
	}
	if !strings.Contains(summary, "libssl.so") {
		t.Error("Summary missing unloaded library name")
	}
}
