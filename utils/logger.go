// Package utils — logger.go
// Colourised, thread-safe terminal logger for Toran_MAP.
package utils

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

var logMu sync.Mutex

// ANSI colour helpers
const (
	colReset  = "\033[0m"
	colRed    = "\033[31m"
	colGreen  = "\033[32m"
	colYellow = "\033[33m"
	colBlue   = "\033[34m"
	colPurple = "\033[35m"
	colCyan   = "\033[36m"
	colWhite  = "\033[37m"
	colBold   = "\033[1m"
)

func ts() string {
	return time.Now().Format("15:04:05")
}

func log(prefix, color, msg string) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Printf("%s[%s]%s %s%s%s %s\n", colBold, ts(), colReset, color, prefix, colReset, msg)
}

// PrintBanner renders the tool banner.
func PrintBanner() {
	banner := `
  ████████╗ ██████╗ ██████╗  █████╗ ███╗   ██╗    ███╗   ███╗ █████╗ ██████╗ 
  ╚══██╔══╝██╔═══██╗██╔══██╗██╔══██╗████╗  ██║    ████╗ ████║██╔══██╗██╔══██╗
     ██║   ██║   ██║██████╔╝███████║██╔██╗ ██║    ██╔████╔██║███████║██████╔╝
     ██║   ██║   ██║██╔══██╗██╔══██║██║╚██╗██║    ██║╚██╔╝██║██╔══██║██╔═══╝ 
     ██║   ╚██████╔╝██║  ██║██║  ██║██║ ╚████║    ██║ ╚═╝ ██║██║  ██║██║     
     ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
`
	fmt.Println(colCyan + banner + colReset)
	fmt.Println(colBold + "  Enterprise-Grade Network Assessment Engine  v2.0.0" + colReset)
	fmt.Println(colYellow + "  ──────────────────────────────────────────────────────────────────" + colReset)
	fmt.Println()
}

// PrintSection prints a labelled section divider.
func PrintSection(title string) {
	logMu.Lock()
	defer logMu.Unlock()
	line := strings.Repeat("─", 60)
	fmt.Printf("\n%s%s%s\n", colCyan+colBold, "  ┌─ "+title+" "+line, colReset)
}

// PrintInfo prints an informational message in blue.
func PrintInfo(msg string) { log("[INFO]", colBlue, msg) }

// PrintSuccess prints a success message in green.
func PrintSuccess(msg string) { log("[OK]  ", colGreen, msg) }

// PrintWarning prints a warning in yellow.
func PrintWarning(msg string) { log("[WARN]", colYellow, msg) }

// PrintError prints an error / vulnerability alert in red.
func PrintError(msg string) { log("[VULN]", colRed, msg) }

// PrintCritical prints a critical finding in purple.
func PrintCritical(msg string) { log("[CRIT]", colPurple, msg) }

// PrintTestingParam prints a compact test progress line.
func PrintTestingParam(param, vectorName string) {
	logMu.Lock()
	defer logMu.Unlock()
	fmt.Printf("%s  ↪ Testing%s %-20s %s[%s]%s\n",
		colCyan, colReset, param+":", colYellow, vectorName, colReset)
}
