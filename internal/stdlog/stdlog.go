// Package stdlog registers two endpoints, /debug/logs/on and /debug/logs/off,
// as a side-effect. When /debug/logs/on is called, the log level of Handler is
// set to debug. When /debug/logs/off is called, the log level of Handler is set
// to info.
package stdlog

import (
	"log/slog"
	"net/http"
	"os"

	"golang.org/x/term"
)

var logLevel = new(slog.LevelVar)

// Handler is a multi-handler that writes human-readable logs to
// stdout and machine-readable logs to stderr.
var Handler slog.Handler = multiHandler([]slog.Handler{
	slog.Handler(slog.NewJSONHandler(os.Stdout,
		&slog.HandlerOptions{AddSource: true, Level: logLevel})),
	slog.Handler(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: logLevel})),
})

func init() {
	// Disable JSON logs if stdout is a terminal.
	if term.IsTerminal(int(os.Stdout.Fd())) {
		Handler = slog.Handler(slog.NewTextHandler(os.Stderr,
			&slog.HandlerOptions{AddSource: true, Level: logLevel}))
	}
}

func init() {
	http.HandleFunc("POST /debug/logs/on", func(w http.ResponseWriter, r *http.Request) {
		logLevel.Set(slog.LevelDebug)
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("POST /debug/logs/off", func(w http.ResponseWriter, r *http.Request) {
		logLevel.Set(slog.LevelInfo)
		w.WriteHeader(http.StatusOK)
	})
	if os.Getenv("DEBUG") != "" {
		logLevel.Set(slog.LevelDebug)
	}
}
