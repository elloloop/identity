package file

import (
	"os"
	"os/signal"
	"syscall"
)

// WatchSIGHUP installs a SIGHUP handler that triggers [Signer.Reload]
// each time the process receives the signal. Returns a stop function
// the caller MUST invoke during shutdown to detach the handler and
// drain the goroutine. Reload errors are passed to the supplied
// callback so the caller can decide whether to log, increment a
// metric, or abort.
//
// Rationale: existing identity entrypoints already use signal.Notify
// for SIGTERM/SIGINT (see cmd/identity/main.go). Reusing the same
// pattern keeps process-signal handling in one place. Operators who
// prefer file-watching can wrap the deployment in a sidecar that
// re-renders keys.json and sends SIGHUP, or extend this package with
// an fsnotify-based driver later — the [Signer.Reload] method is the
// single source of truth either way.
func WatchSIGHUP(s *Signer, onError func(error)) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ch:
				if err := s.Reload(); err != nil && onError != nil {
					onError(err)
				}
			case <-done:
				return
			}
		}
	}()

	return func() {
		signal.Stop(ch)
		close(done)
	}
}
