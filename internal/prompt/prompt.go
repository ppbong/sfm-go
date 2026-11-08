package prompt

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"sfm/internal/crypto"

	"golang.org/x/term"
)

func ReadPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)

	if err != nil {
		reader := bufio.NewReader(os.Stdin)
		line, err2 := reader.ReadString('\n')
		if err2 != nil && err2 != io.EOF {
			return "", err2
		}

		return strings.TrimRight(line, "\r\n"), nil
	}

	return string(pwd), nil
}

func ReadPasswordTwice() (string, error) {
	p1, err := ReadPassword("Enter password: ")
	if err != nil {
		return "", err
	}

	if len(p1) < 6 {
		return "", fmt.Errorf("password must be at least 6 characters")
	}

	p2, err := ReadPassword("Confirm password: ")
	if err != nil {
		return "", err
	}

	if p1 != p2 {
		return "", fmt.Errorf("passwords do not match")
	}

	return p1, nil
}

func ChooseAlgSuite() (crypto.AlgSuite, error) {
	fmt.Fprintln(os.Stderr, "Select algorithm suite:")
	fmt.Fprintln(os.Stderr, "  1) RSA-4096 + AES-256-GCM  (recommended)")
	fmt.Fprintln(os.Stderr, "  2) SM2 + SM4  (Chinese national standard)")
	fmt.Fprint(os.Stderr, "Choice [1/2] (default 1): ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return 0, err
	}

	line = strings.TrimSpace(line)
	if line == "" {
		return crypto.AlgRsaAes, nil
	}

	switch line {
	case "1", "rsa", "RSA":
		return crypto.AlgRsaAes, nil
	case "2", "sm2", "SM2":
		return crypto.AlgSm2Sm4, nil
	}

	return 0, fmt.Errorf("invalid choice: %s", line)
}

func ReadLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}

	return strings.TrimSpace(line), nil
}
