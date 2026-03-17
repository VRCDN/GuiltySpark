// Package logger wraps log/slog with a constructor and some context helpers.
// Both binaries use this so they get consistent output.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

type contextKey int

const loggerKey contextKey = iota

// Logger is just slog.Logger with a constructor and context helpers.
type Logger struct {
	*slog.Logger
}

// New creates a logger. format is "json" or "text", level is "debug"/"info"/"warn"/"error".
func New(format, level string) *Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if strings.ToLower(format) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return &Logger{slog.New(handler)}
}

// NewWithWriter is the same as New but lets you specify the output writer.
func NewWithWriter(w io.Writer, format, level string) *Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if strings.ToLower(format) == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	return &Logger{slog.New(handler)}
}

// WithContext stashes the logger in a context so it can be retrieved later.
func WithContext(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}

// FromContext retrieves the logger from context. Falls back to a plain info logger if there isn't one.
func FromContext(ctx context.Context) *Logger {
	if l, ok := ctx.Value(loggerKey).(*Logger); ok {
		return l
	}
	return New("text", "info")
}

// With returns a child logger with extra fields attached.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{l.Logger.With(args...)}
}
