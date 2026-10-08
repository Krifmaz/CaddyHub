// Package web embeds the built frontend. The UI is built into ui/dist
// (see frontend/vite.config.js); without a build the server still runs and
// shows a hint instead of the UI.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:ui
var ui embed.FS

// FS returns the built UI, or nil if it wasn't built.
func FS() fs.FS {
	sub, err := fs.Sub(ui, "ui/dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return sub
}
