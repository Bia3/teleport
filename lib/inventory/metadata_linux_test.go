//go:build linux
// +build linux

/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package inventory

import (
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

func TestFetchOSVersion(t *testing.T) {
	t.Parallel()

	expectedFormat0 := `
PRETTY_NAME="Ubuntu 22.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.1 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
`

	expectedFormat1 := `
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
`

	unexpectedFormat := `
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
name="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
`

	testCases := []struct {
		desc        string
		readFile func(string) ([]byte, error)
		expected    string
	}{
		{
			desc: "set correctly if expected format 0",
			readFile: func(name string) ([]byte, error) {
				if name != "/etc/os-release" {
					return nil, trace.NotFound("file does not exist")
				}
				return []byte(expectedFormat0), nil
			},
			expected: "Ubuntu 22.04",
		},
		{
			desc: "set correctly if expected format 1",
			readFile: func(name string) ([]byte, error) {
				if name != "/etc/os-release" {
					return nil, trace.NotFound("file does not exist")
				}
				return []byte(expectedFormat1), nil
			},
			expected: "Debian GNU/Linux 11",
		},
		{
			desc: "full content if unexpected format",
			readFile: func(name string) ([]byte, error) {
				if name != "/etc/os-release" {
					return nil, trace.NotFound("file does not exist")
				}
				return []byte(unexpectedFormat), nil
			},
			expected: sanitize(unexpectedFormat),
		},
		{
			desc: "empty if /etc/os-release does not exist",
			readFile: func(name string) ([]byte, error) {
				return nil, trace.NotFound("file does not exist")
			},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			c := &fetchConfig{
				readFile: tc.readFile,
			}
			require.Equal(t, tc.expected, c.fetchOSVersion())
		})
	}
}