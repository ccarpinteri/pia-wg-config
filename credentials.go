package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"unicode/utf8"
)

const maxCredentialInputSize = 8 * 1024

var (
	errInvalidCredentialDescriptor = errors.New("invalid credential descriptor")
	errReadCredentials             = errors.New("failed to read credentials")
	errCredentialInputTooLarge     = errors.New("credential input exceeds limit")
	errInvalidCredentialInput      = errors.New("invalid credential input")
)

type credentials struct {
	username string
	password string
}

func credentialsFromInvocation(fdMode bool, fd int, args []string) (credentials, error) {
	if !fdMode {
		return credentials{
			username: argument(args, 0),
			password: argument(args, 1),
		}, nil
	}
	if len(args) != 0 {
		return credentials{}, errInvalidCredentialDescriptor
	}
	if fd < 3 {
		return credentials{}, errInvalidCredentialDescriptor
	}

	file := os.NewFile(uintptr(fd), "credentials")
	if file == nil {
		return credentials{}, errInvalidCredentialDescriptor
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxCredentialInputSize+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return credentials{}, errReadCredentials
	}
	if len(raw) > maxCredentialInputSize {
		return credentials{}, errCredentialInputTooLarge
	}
	return parseCredentials(raw)
}

func argument(args []string, index int) string {
	if index >= len(args) {
		return ""
	}
	return args[index]
}

func parseCredentials(raw []byte) (credentials, error) {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return credentials{}, errInvalidCredentialInput
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return credentials{}, errInvalidCredentialInput
	}

	values := make(map[string]string, 2)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "username" && key != "password") {
			return credentials{}, errInvalidCredentialInput
		}
		if _, duplicate := values[key]; duplicate {
			return credentials{}, errInvalidCredentialInput
		}
		var value string
		if err := decoder.Decode(&value); err != nil || value == "" {
			return credentials{}, errInvalidCredentialInput
		}
		values[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return credentials{}, errInvalidCredentialInput
	}
	if decoder.InputOffset() != int64(len(raw)) {
		return credentials{}, errInvalidCredentialInput
	}
	if err := requireJSONEOF(decoder); err != nil {
		return credentials{}, errInvalidCredentialInput
	}
	if len(values) != 2 {
		return credentials{}, errInvalidCredentialInput
	}
	return credentials{username: values["username"], password: values["password"]}, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return errInvalidCredentialInput
}
