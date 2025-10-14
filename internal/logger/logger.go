package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// CLIHandler provides clean output for CLI applications
type CLIHandler struct {
	writer io.Writer
	level  slog.Level
}

// NewCLIHandler creates a new CLI handler
func NewCLIHandler(w io.Writer, level slog.Level) *CLIHandler {
	return &CLIHandler{
		writer: w,
		level:  level,
	}
}

// Enabled reports whether the handler handles records at the given level
func (h *CLIHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle formats and writes the log record
func (h *CLIHandler) Handle(_ context.Context, r slog.Record) error {
	msg := r.Message

	// Add level prefix for warnings and errors
	switch r.Level {
	case slog.LevelWarn:
		msg = "⚠️  " + msg
	case slog.LevelError:
		msg = "❌ " + msg
	}

	_, err := fmt.Fprintln(h.writer, msg)
	return err
}

// WithAttrs returns a new handler with the given attributes
func (h *CLIHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	_ = attrs // no-op for CLI handler
	return h
}

// WithGroup returns a new handler with the given group
func (h *CLIHandler) WithGroup(name string) slog.Handler {
	_ = name // no-op for CLI handler
	return h
}

// Logger wraps slog.Logger with convenience methods
type Logger struct {
	*slog.Logger
}

// NewCLILogger creates a new logger with CLI handler
func NewCLILogger() *Logger {
	handler := NewCLIHandler(os.Stdout, slog.LevelInfo)
	return &Logger{slog.New(handler)}
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	l.Logger.Info(msg)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string) {
	l.Logger.Warn(msg)
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	l.Logger.Error(msg)
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Logger.Info(fmt.Sprintf(format, args...))
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Logger.Warn(fmt.Sprintf(format, args...))
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Logger.Error(fmt.Sprintf(format, args...))
}
