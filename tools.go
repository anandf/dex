//go:build tools

package main

import (
	_ "github.com/mattn/go-runewidth"
	_ "github.com/olekukonko/tablewriter"
	_ "golang.org/x/sync/syncmap"
	_ "golang.org/x/tools/imports"
)
