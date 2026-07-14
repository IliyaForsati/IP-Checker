package logging

import (
	"fmt"
	"log/slog"
	"os"
)

func New(level, path string) (*slog.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}

	out := os.Stdout
	if path != "" && path != "stdout" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("logging: open %s: %w", path, err)
		}
		out = f
	}

	handler := slog.NewJSONHandler(out, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler), nil
}

func parseLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging: unknown level %q", level)
	}
}
