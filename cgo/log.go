package main

import (
	"os"

	"github.com/decred/slog"
	"github.com/jrick/logrotate/rotator"
)

type parentLogger struct {
	*slog.Backend
	rotator *rotator.Rotator
	lvl     slog.Level
}

func newParentLogger(rotator *rotator.Rotator, lvl slog.Level) *parentLogger {
	return &parentLogger{
		Backend: slog.NewBackend(rotator),
		rotator: rotator,
		lvl:     lvl,
	}
}

func newParentStdOutLogger(lvl slog.Level) *parentLogger {
	backend := slog.NewBackend(os.Stdout)
	return &parentLogger{
		Backend: backend,
		lvl:     lvl,
	}
}

func (pl *parentLogger) SubLogger(name string) slog.Logger {
	logger := pl.Logger(name)
	logger.SetLevel(pl.lvl)
	return logger
}

func (pl *parentLogger) Close() error {
	if pl.rotator != nil {
		return pl.rotator.Close()
	}
	return nil
}
