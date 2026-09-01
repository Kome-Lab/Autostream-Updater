//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func defaultReadHostAgentConfigureToken(ctx context.Context) (string, error) {
	return readLinuxHostAgentConfigureToken(ctx, os.Stdin, os.Stderr)
}

func readLinuxHostAgentConfigureToken(ctx context.Context, input *os.File, prompt io.Writer) (token string, resultErr error) {
	fd := int(input.Fd())
	termios, termiosErr := unix.IoctlGetTermios(fd, unix.TCGETS)
	isTerminal := termiosErr == nil
	if termiosErr != nil && !errors.Is(termiosErr, unix.ENOTTY) && !errors.Is(termiosErr, unix.EINVAL) {
		return "", errors.New("inspect standard input terminal")
	}
	if isTerminal {
		noEcho := *termios
		noEcho.Lflag &^= unix.ECHO
		if err := unix.IoctlSetTermios(fd, unix.TCSETS, &noEcho); err != nil {
			return "", errors.New("disable terminal echo for Configure Token")
		}
		_, _ = fmt.Fprint(prompt, "Configure Token: ")
		defer func() {
			restoreErr := unix.IoctlSetTermios(fd, unix.TCSETS, termios)
			_, _ = fmt.Fprintln(prompt)
			if resultErr == nil && restoreErr != nil {
				token = ""
				resultErr = errors.New("restore terminal echo after Configure Token input")
			}
		}()
	}
	return readHostAgentConfigureTokenFD(ctx, fd)
}

func readHostAgentConfigureTokenFD(ctx context.Context, fd int) (string, error) {
	input := make([]byte, 0, 128)
	buffer := make([]byte, 256)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		pollFDs := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP}}
		ready, err := unix.Poll(pollFDs, 100)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", errors.New("wait for Configure Token on standard input")
		}
		if ready == 0 {
			continue
		}
		if pollFDs[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return "", errors.New("standard input failed while reading Configure Token")
		}
		read, readErr := unix.Read(fd, buffer)
		if read > 0 {
			for _, value := range buffer[:read] {
				input = append(input, value)
				if len(input) > hostAgentConfigureTokenMaxBytes+2 {
					return "", errors.New("Configure Token from standard input is too large")
				}
				if value == '\n' {
					return normalizeHostAgentConfigureToken(input)
				}
			}
		}
		if readErr != nil && !errors.Is(readErr, unix.EINTR) && !errors.Is(readErr, unix.EAGAIN) {
			return "", errors.New("read Configure Token from standard input")
		}
		if read == 0 || pollFDs[0].Revents&unix.POLLHUP != 0 {
			return normalizeHostAgentConfigureToken(input)
		}
	}
}
