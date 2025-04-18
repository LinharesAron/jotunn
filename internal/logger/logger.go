package logger

import (
	"fmt"
	"log"
	"os"
)

var fileLogger *log.Logger
var enableFile bool = false

func Init(path string) {
	if path == "" {
		return
	}

	logFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stdout, "\033[31m[ERROR] Failed to create log file: %v\033[0m\n", err)
		return
	}

	fileLogger = log.New(logFile, "", log.LstdFlags)
	enableFile = true
}

func logWithColor(colorCode string, prefix string, msg string) {
	fmt.Fprint(os.Stdout, "\033[2K\r")

	fmt.Fprintln(os.Stderr, colorCode+prefix+msg+"\033[0m")
	if Progress != nil {
		Progress.renderInline()
	}
}

func Info(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWithColor("\033[33m", "[INFO] ", msg)
	if enableFile {
		fileLogger.Printf("[INFO] %s", msg)
	}
}

func Error(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWithColor("\033[31m", "[ERROR] ", msg)
	if enableFile {
		fileLogger.Println("[ERROR]", fmt.Sprint(args...))
	}
}

func Success(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	logWithColor("\033[32m", "[SUCCESS] ", msg)
	if enableFile {
		fileLogger.Println("[SUCCESS]", fmt.Sprint(args...))
	}
}
