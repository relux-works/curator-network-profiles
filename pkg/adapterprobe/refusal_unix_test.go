// SPDX-License-Identifier: Apache-2.0
//go:build darwin || linux

package adapterprobe

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFIFOAndNonCLOEXECParentDescriptor(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	// A genuinely non-CLOEXEC descriptor is opened only on a disposable canary.
	// Fresh probing refuses; it cannot expose it to a child or close it in parent.
	fd, err := syscall.Open(filepath.Join(dir, "descriptor-canary"), syscall.O_CREAT|syscall.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	req := request()
	req.Binary = fifo
	type outcome struct {
		result Result
		err    error
	}
	done := make(chan []outcome, 1)
	go func() {
		res, err := Verified(context.Background(), req, fifo, Policy{})
		first := outcome{res, err}
		req.Artifact = nil
		res, err = Probe(context.Background(), req)
		done <- []outcome{first, {res, err}}
	}()
	select {
	case outcomes := <-done:
		assertFailure(t, outcomes[0].result, outcomes[0].err, "persistent_cache_unsupported")
		assertFailure(t, outcomes[1].result, outcomes[1].err, "artifact_snapshot_required")
	case <-time.After(time.Second):
		t.Fatal("probe blocked opening FIFO")
	}
	if _, err := syscall.Write(fd, []byte("disposable-canary")); err != nil {
		t.Fatal("closed parent descriptor")
	}
}
