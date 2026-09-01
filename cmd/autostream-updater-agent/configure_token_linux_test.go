//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxHostAgentConfigureTokenPipeCancellationIsPrompt(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(25*time.Millisecond, cancel)
	started := time.Now()
	_, err = readLinuxHostAgentConfigureToken(ctx, reader, &strings.Builder{})
	if !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
		t.Fatalf("cancelled Host Agent token read err=%v elapsed=%s", err, time.Since(started))
	}
}

func TestLinuxHostAgentConfigureTokenTTYDisablesAndRestoresEcho(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	ptyNumber, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", ptyNumber), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	original, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	configured := *original
	configured.Lflag |= unix.ECHO | unix.ICANON
	if err := unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, &configured); err != nil {
		t.Fatal(err)
	}
	defer unix.IoctlSetTermios(int(slave.Fd()), unix.TCSETS, original)

	type result struct {
		token string
		err   error
	}
	prompt := &strings.Builder{}
	resultCh := make(chan result, 1)
	go func() {
		token, err := readLinuxHostAgentConfigureToken(context.Background(), slave, prompt)
		resultCh <- result{token: token, err: err}
	}()
	deadline := time.Now().Add(time.Second)
	for {
		current, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if current.Lflag&unix.ECHO == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal echo was not disabled before Host Agent token input")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := master.Write([]byte("tty-host-agent-configure-secret\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-resultCh:
		if got.err != nil || got.token != "tty-host-agent-configure-secret" {
			t.Fatalf("TTY Host Agent token=%q err=%v", got.token, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("TTY Host Agent token read did not complete")
	}
	restored, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Lflag&unix.ECHO == 0 || strings.Contains(prompt.String(), "tty-host-agent-configure-secret") {
		t.Fatalf("terminal echo was not safely restored; prompt=%q", prompt.String())
	}
}
