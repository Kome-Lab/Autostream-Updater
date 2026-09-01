package main

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

const hostAgentConfigureTokenMaxBytes = 4096

func readBoundedHostAgentConfigureToken(input io.Reader) (string, error) {
	reader := bufio.NewReader(io.LimitReader(input, hostAgentConfigureTokenMaxBytes+2))
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errors.New("read Configure Token from standard input")
	}
	return normalizeHostAgentConfigureToken([]byte(line))
}

func normalizeHostAgentConfigureToken(input []byte) (string, error) {
	token := strings.TrimSpace(string(input))
	if token == "" {
		return "", errors.New("Configure Token is required on standard input")
	}
	if len(token) > hostAgentConfigureTokenMaxBytes {
		return "", errors.New("Configure Token from standard input is too large")
	}
	return token, nil
}
