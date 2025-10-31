package txfuzz

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// CompactHandler is a custom slog.Handler that formats logs in a clean, readable format.
// Format: HH:MM:SS.mmm LEVEL message
type CompactHandler struct {
	w     io.Writer
	level slog.Level
}

// NewCompactHandler creates a new CompactHandler with the specified writer and options.
func NewCompactHandler(w io.Writer, opts *slog.HandlerOptions) *CompactHandler {
	h := &CompactHandler{w: w}
	if opts != nil {
		h.level = opts.Level.Level()
	}
	return h
}

func (h *CompactHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *CompactHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder

	// Format time as HH:MM:SS.mmm
	t := r.Time.Format("15:04:05.000")
	b.WriteString(t)
	b.WriteString(" ")

	// Add level (4 chars wide for alignment)
	level := r.Level.String()
	b.WriteString(fmt.Sprintf("%-4s", level))
	b.WriteString(" ")

	// Add message
	b.WriteString(r.Message)

	b.WriteString("\n")

	_, err := h.w.Write([]byte(b.String()))
	return err
}

func (h *CompactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// Not needed for our use case, but required by interface
	return h
}

func (h *CompactHandler) WithGroup(name string) slog.Handler {
	// Not needed for our use case, but required by interface
	return h
}
