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

package common

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/utils"
)

func TestAgentless(t *testing.T) {
	t.Parallel()

	clock := clockwork.NewFakeClock()
	tt, err := auth.NewTestAuthServer(auth.TestAuthServerConfig{
		ClusterName: "cluster",
		Dir:         t.TempDir(),
		Clock:       clock,
	})
	require.NoError(t, err)
	defer tt.Close()

	server, err := tt.NewTestTLSServer()
	require.NoError(t, err)
	defer server.Close()

	require.NoError(t, server.Auth().UpsertNamespace(types.DefaultNamespace()))

	testdir := t.TempDir()
	addr := utils.FromAddr(server.Addr())
	uuid := uuid.NewString()

	keysDir := filepath.Join(testdir, "keys")
	backupKeysDir := filepath.Join(testdir, "keys_backup")

	agentlessSSHDConfigPath = filepath.Join(testdir, "agentless_sshd.conf")
	agentlessSSHDConfigInclude = "Include " + agentlessSSHDConfigPath

	var sshdRestarted bool
	ag := agentless{
		uuid:                 uuid,
		principals:           []string{uuid},
		hostname:             "hostname",
		proxyAddr:            &addr,
		accountID:            "acid",
		instanceID:           "inst",
		instanceAddr:         "localhost:22",
		imds:                 nil,
		defaultKeysDir:       keysDir,
		defaultBackupKeysDir: backupKeysDir,
		clock:                clock,
		restartSSHD: func() error {
			sshdRestarted = true
			return nil
		},
		checkSSHD: func(path string) error {
			return nil
		},
	}

	ctx := context.Background()

	token, err := types.NewProvisionToken("join-token", types.SystemRoles{
		types.RoleNode,
	}, clock.Now().Add(10*time.Minute))
	require.NoError(t, err)

	require.NoError(t, server.Auth().CreateToken(ctx, token))

	configPath := filepath.Join(testdir, "config")
	cfgFile, err := os.Create(configPath)
	require.NoError(t, err)
	require.NoError(t, cfgFile.Close())

	clf := config.CommandLineFlags{
		OpenSSHKeysPath:       keysDir,
		OpenSSHKeysBackupPath: backupKeysDir,
		OpenSSHConfigPath:     configPath,
		NodeName:              uuid,
		FIPS:                  false,
		JoinMethod:            "token",
		AuthToken:             "join-token",
		InsecureMode:          true,
		RestartOpenSSH:        true,
	}

	err = ag.openSSHJoin(ctx, clf)
	require.NoError(t, err)
	_, err = server.Auth().GetNode(ctx, "default", uuid)
	require.NoError(t, err)

	checkKeysExist(t, keysDir)
	require.True(t, sshdRestarted)
	checkConfigFile(t, keysDir, configPath, agentlessSSHDConfigPath)
	compareCAFiles(t, ctx, server.Auth(), filepath.Join(keysDir, teleportOpenSSHCA))

	rotate(ctx, t, server.Auth())
	err = ag.openSSHJoin(ctx, clf)

	require.NoError(t, err)
	checkKeysExist(t, backupKeysDir)
	compareCAFiles(t, ctx, server.Auth(), filepath.Join(keysDir, teleportOpenSSHCA))

	err = server.Auth().RotateCertAuthority(ctx, auth.RotateRequest{
		Type:        types.OpenSSHCA,
		TargetPhase: types.RotationPhaseRollback,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)

	err = ag.openSSHRollback(ctx, clf)
	require.NoError(t, err)
	checkKeysExist(t, keysDir)
	_, err = os.Stat(backupKeysDir)
	require.True(t, os.IsNotExist(err))
}

func compareCAFiles(t *testing.T, ctx context.Context, server *auth.Server, caFile string) {
	t.Helper()
	contents, err := os.ReadFile(caFile)
	require.NoError(t, err)
	cas, err := server.GetCertAuthorities(ctx, types.OpenSSHCA, false)
	require.NoError(t, err)

	var openSSHCA []byte
	for _, ca := range cas {
		for _, key := range ca.GetTrustedSSHKeyPairs() {
			openSSHCA = append(openSSHCA, key.PublicKey...)
		}
	}
	require.Equal(t, string(openSSHCA), string(contents))
}

func checkConfigFile(t *testing.T, keyDir, configPath, teleportAgentlessPath string) {
	t.Helper()
	configContents, err := os.ReadFile(configPath)
	require.NoError(t, err)
	require.Equal(t, "Include "+teleportAgentlessPath+"\n", string(configContents))

	expected := fmt.Sprintf(`%s
TrustedUserCaKeys %s
HostKey %s
HostCertificate %s
`,
		sshdConfigSectionModificationHeader,
		filepath.Join(keyDir, "teleport_user_ca.pub"),
		filepath.Join(keyDir, "teleport"),
		filepath.Join(keyDir, "teleport-cert.pub"),
	)
	configContents, err = os.ReadFile(teleportAgentlessPath)
	require.NoError(t, err)

	require.Equal(t, expected, string(configContents))
}

func checkKeysExist(t *testing.T, keysDir string) {
	t.Helper()
	for _, keyfile := range []string{teleportKey, teleportCert, teleportOpenSSHCA} {
		_, err := os.Stat(filepath.Join(keysDir, keyfile))
		require.NoError(t, err)
	}
}

func rotate(ctx context.Context, t *testing.T, server *auth.Server) {
	t.Helper()

	err := server.RotateCertAuthority(ctx, auth.RotateRequest{
		Type:        types.OpenSSHCA,
		TargetPhase: types.RotationPhaseInit,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)

	err = server.RotateCertAuthority(ctx, auth.RotateRequest{
		Type:        types.OpenSSHCA,
		TargetPhase: types.RotationPhaseUpdateClients,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)

	err = server.RotateCertAuthority(ctx, auth.RotateRequest{
		Type:        types.OpenSSHCA,
		TargetPhase: types.RotationPhaseUpdateServers,
		Mode:        types.RotationModeManual,
	})
	require.NoError(t, err)
}
