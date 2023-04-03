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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/auth/native"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/cloud/aws"
	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const sshdBinary = "sshd"

const sshdConfigSectionModificationHeader = "### Created by 'teleport join openssh', do not edit"

const (
	// agentlessSSHDConfigPath is the path to write teleport specific SSHD config options
	agentlessSSHDConfigPath = "/etc/teleport/agentless_sshd.conf"
	// agentlessSSHDConfig is Include directive added to the sshd_config file
	agentlessSSHDConfigInclude = "Include " + agentlessSSHDConfigPath
	// agentlessKeys is the path to write agentless openssh keys
	agentlessKeysDir = "/etc/teleport/agentless"
	// agentlessKeys is the path to write agentless openssh keys for
	// use on rollback
	agentlessKeysBackupDir = "/etc/teleport/agentless_backup"
)

const (
	teleportKey       = "teleport"
	teleportCert      = "teleport-cert.pub"
	teleportTLSCert   = "teleport-tls-cert.pub"
	teleportOpenSSHCA = "teleport_user_ca.pub"
	teleportSSHHostCA = "teleport_ssh_host_ca.pub"
	teleportTLSHostCA = "teleport_tls_host_ca.pub"
)

type agentlessKeys struct {
	privateKey                      []byte
	certs                           *proto.Certs
	openSSHCA, hostSSHCA, hostTLSCA []byte
}

func writeKeys(keysDir string, keys agentlessKeys) error {
	if err := os.WriteFile(filepath.Join(keysDir, teleportKey), keys.privateKey, 0600); err != nil {
		return trace.Wrap(err)
	}

	if err := os.WriteFile(filepath.Join(keysDir, teleportCert), keys.certs.SSH, 0600); err != nil {
		return trace.Wrap(err)
	}

	if err := os.WriteFile(filepath.Join(keysDir, teleportTLSCert), keys.certs.TLS, 0600); err != nil {
		return trace.Wrap(err)
	}

	if err := os.WriteFile(filepath.Join(keysDir, teleportOpenSSHCA), keys.openSSHCA, 0600); err != nil {
		return trace.Wrap(err)
	}

	if err := os.WriteFile(filepath.Join(keysDir, teleportSSHHostCA), keys.hostSSHCA, 0600); err != nil {
		return trace.Wrap(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, teleportTLSHostCA), keys.hostTLSCA, 0600); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// GenerateKeys generates TLS and SSH keypairs.
func GenerateKeys() (privateKey, publicKey, tlsPublicKey []byte, err error) {
	privateKey, publicKey, err = native.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}

	sshPrivateKey, err := ssh.ParseRawPrivateKey(privateKey)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}

	tlsPublicKey, err = tlsca.MarshalPublicKeyFromPrivateKeyPEM(sshPrivateKey)
	if err != nil {
		return nil, nil, nil, trace.Wrap(err)
	}
	return privateKey, publicKey, tlsPublicKey, nil
}

func ReadKeys(clf config.CommandLineFlags) (privateKey, publicKey, tlsPublicKey []byte, certs *proto.Certs, err error) {
	privateKey, err = os.ReadFile(filepath.Join(clf.OpenSSHKeysPath, teleportKey))
	if err != nil {
		return nil, nil, nil, nil, trace.ConvertSystemError(err)
	}

	publicKey, err = os.ReadFile(filepath.Join(clf.OpenSSHKeysPath, teleportCert))
	if err != nil {
		return nil, nil, nil, nil, trace.Wrap(err)
	}

	tlsPublicKey, err = os.ReadFile(filepath.Join(clf.OpenSSHKeysPath, teleportTLSCert))
	if err != nil {
		return nil, nil, nil, nil, trace.Wrap(err)
	}

	hostTLSCAContents, err := os.ReadFile(filepath.Join(clf.OpenSSHKeysPath, teleportTLSHostCA))
	if err != nil {
		return nil, nil, nil, nil, trace.Wrap(err)
	}

	var hostTLSCAs [][]byte
	for block, rest := pem.Decode(hostTLSCAContents); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			hostTLSCAs = append(hostTLSCAs, pem.EncodeToMemory(block))
		default:
			return nil, nil, nil, nil, trace.BadParameter("invalid block: %s", block.Type)
		}

	}

	hostSSHCAContents, err := os.ReadFile(filepath.Join(clf.OpenSSHKeysPath, teleportSSHHostCA))
	if err != nil {
		return nil, nil, nil, nil, trace.Wrap(err)
	}

	certs = &proto.Certs{
		SSH:        publicKey,
		TLS:        tlsPublicKey,
		TLSCACerts: hostTLSCAs,
		SSHCACerts: bytes.Split(bytes.TrimSpace(hostSSHCAContents), []byte("\n")),
	}
	return privateKey, publicKey, tlsPublicKey, certs, nil
}

func authenticatedUserClientFromIdentity(ctx context.Context, insecure, fips bool, proxy utils.NetAddr, id *auth.Identity) (auth.ClientI, error) {
	var tlsConfig *tls.Config
	var err error
	var cipherSuites []uint16
	if fips {
		cipherSuites = defaults.FIPSCipherSuites
	}

	tlsConfig, err = id.TLSConfig(cipherSuites)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	tlsConfig.InsecureSkipVerify = insecure

	sshConfig, err := id.SSHClientConfig(fips)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	authClientConfig := &authclient.Config{
		TLS:         tlsConfig,
		SSH:         sshConfig,
		AuthServers: []utils.NetAddr{proxy},
		Log:         log.StandardLogger(),
	}

	c, err := authclient.Connect(ctx, authClientConfig)

	return c, trace.Wrap(err)
}

func getAWSInstanceHostname(ctx context.Context, imds agentlessIMDS) (string, error) {
	hostname, err := imds.GetHostname(ctx)
	if err != nil {
		return "", trace.Wrap(err)
	}
	hostname = strings.ReplaceAll(hostname, " ", "_")
	if utils.IsValidHostname(hostname) {
		return hostname, nil
	}
	return "", trace.NotFound("failed to get a valid hostname from IMDS")
}

func tryCreateDefaultAgentlesKeysDir(agentlessKeysPath string) error {
	baseTeleportDir := filepath.Dir(agentlessKeysPath)
	_, err := os.Stat(baseTeleportDir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debugf("%s did not exist, creating %s", baseTeleportDir, agentlessKeysPath)
			return trace.Wrap(os.MkdirAll(agentlessKeysPath, 0700))
		}
		return trace.Wrap(err)
	}

	var alreadyExistedAndDeleted bool
	_, err = os.Stat(agentlessKeysPath)
	if err == nil {
		log.Debugf("%s already existed, removing old files", agentlessKeysPath)
		err = os.RemoveAll(agentlessKeysPath)
		if err != nil {
			return trace.Wrap(err)
		}
		alreadyExistedAndDeleted = true
	}

	if os.IsNotExist(err) || alreadyExistedAndDeleted {
		log.Debugf("%s did not exist, creating", agentlessKeysPath)
		return trace.Wrap(os.Mkdir(agentlessKeysPath, 0700))
	}

	return trace.Wrap(err)
}

type agentless struct {
	uuid                 string
	principals           []string
	hostname             string
	proxyAddr            *utils.NetAddr
	imds                 agentlessIMDS
	defaultKeysDir       string
	defaultBackupKeysDir string
	restartSSHD          func() error
	clock                clockwork.Clock
	accountID            string
	instanceID           string
	instanceAddr         string
	region               string
}

type agentlessIMDS interface {
	GetHostname(context.Context) (string, error)
	GetAccountID(context.Context) (string, error)
	GetID(context.Context) (string, error)
}

func newAgentless(ctx context.Context, clf config.CommandLineFlags) (*agentless, error) {
	addr, err := utils.ParseAddr(clf.ProxyServer)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	imds, err := aws.NewInstanceMetadataClient(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	hostname, err := getAWSInstanceHostname(ctx, imds)
	if err != nil {
		var hostErr error
		hostname, hostErr = os.Hostname()
		if hostErr != nil {
			return nil, trace.NewAggregate(err, hostErr)
		}
	}

	publicIP, err := imds.GetPublicIPV4(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	localIP, err := imds.GetLocalIPV4(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	accountID, err := imds.GetAccountID(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	instanceID, err := imds.GetID(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	nodeUUID := fmt.Sprintf("%s-%s", accountID, instanceID)

	principals := []string{nodeUUID, publicIP, localIP, hostname}
	for _, principal := range strings.Split(clf.AdditionalPrincipals, ",") {
		if principal == "" {
			continue
		}
		principals = append(principals, principal)
	}

	var instAddr string
	if publicIP != "" {
		instAddr = fmt.Sprintf("%s:22", publicIP)
	}
	if instAddr == "" && localIP != "" {
		instAddr = fmt.Sprintf("%s:22", localIP)
	}

	region, err := imds.GetRegion(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &agentless{
		uuid:                 nodeUUID,
		principals:           principals,
		hostname:             hostname,
		proxyAddr:            addr,
		imds:                 imds,
		defaultKeysDir:       agentlessKeysDir,
		defaultBackupKeysDir: agentlessKeysBackupDir,
		restartSSHD:          restartSSHD,
		accountID:            accountID,
		instanceID:           instanceID,
		instanceAddr:         instAddr,
		region:               region,
		clock:                clockwork.FromContext(ctx),
	}, nil
}

func (a *agentless) register(clf config.CommandLineFlags, sshPublicKey, tlsPublicKey []byte) (*proto.Certs, error) {
	registerParams := auth.RegisterParams{
		Token:                clf.AuthToken,
		AdditionalPrincipals: a.principals,
		JoinMethod:           types.JoinMethod(clf.JoinMethod),
		ID: auth.IdentityID{
			Role:     types.RoleNode,
			NodeName: a.hostname,
			HostUUID: a.uuid,
		},
		AuthServers:        []utils.NetAddr{*a.proxyAddr},
		PublicTLSKey:       tlsPublicKey,
		PublicSSHKey:       sshPublicKey,
		GetHostCredentials: client.HostCredentials,
		FIPS:               clf.FIPS,
		CAPins:             clf.CAPins,
		Clock:              a.clock,
	}

	if clf.FIPS {
		registerParams.CipherSuites = defaults.FIPSCipherSuites
	}

	certs, err := auth.Register(registerParams)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return certs, trace.Wrap(err)
}

func (a *agentless) getHostCA(ctx context.Context, client auth.ClientI) (hostSSHCA []byte, hostTLSCA []byte, err error) {
	cas, err := client.GetCertAuthorities(ctx, types.HostCA, false)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	for _, ca := range cas {
		for _, key := range ca.GetTrustedSSHKeyPairs() {
			hostSSHCA = append(hostSSHCA, key.PublicKey...)
		}
		for _, key := range ca.GetTrustedTLSKeyPairs() {
			hostTLSCA = append(hostTLSCA, key.Cert...)
		}
	}

	return hostSSHCA, hostTLSCA, nil
}

func (a *agentless) getOpenSSHCA(ctx context.Context, client auth.ClientI) ([]byte, error) {
	cas, err := client.GetCertAuthorities(ctx, types.OpenSSHCA, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var openSSHCA []byte
	for _, ca := range cas {
		for _, key := range ca.GetTrustedSSHKeyPairs() {
			openSSHCA = append(openSSHCA, key.PublicKey...)
		}
	}

	return openSSHCA, nil
}

func (a *agentless) updateKeysAndConfig(ctx context.Context, clf config.CommandLineFlags, newKeys agentlessKeys) error {
	exists, err := a.existingKeysPresent(clf)
	if err != nil {
		return trace.Wrap(err)
	}
	configuredHostKeys := []string{filepath.Join(clf.OpenSSHKeysPath, teleportKey)}
	configuredHostCerts := []string{filepath.Join(clf.OpenSSHKeysPath, teleportCert)}
	if exists {
		if err := os.RemoveAll(clf.OpenSSHKeysBackupPath); err != nil {
			return trace.Wrap(err)
		}
		if err := os.Rename(clf.OpenSSHKeysPath, clf.OpenSSHKeysBackupPath); err != nil {
			return trace.Wrap(err)
		}
	}

	if err := tryCreateDefaultAgentlesKeysDir(clf.OpenSSHKeysPath); err != nil {
		return trace.Wrap(err)
	}

	fmt.Printf("Writing Teleport keys to %s\n", clf.OpenSSHKeysPath)
	if err := writeKeys(clf.OpenSSHKeysPath, newKeys); err != nil {
		if a.defaultKeysDir == clf.OpenSSHKeysPath {
			rmdirErr := os.RemoveAll(a.defaultKeysDir)
			if rmdirErr != nil {
				return trace.NewAggregate(err, rmdirErr)
			}
		}
		return trace.Wrap(err)
	}

	fmt.Println("Updating OpenSSH config")
	if err := updateSSHDConfig(
		clf.OpenSSHConfigPath,
		agentlessSSHDConfigPath,
		filepath.Join(clf.OpenSSHKeysPath, teleportOpenSSHCA),
		configuredHostKeys,
		configuredHostCerts,
	); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (a *agentless) existingKeysPresent(clf config.CommandLineFlags) (bool, error) {
	_, err := os.Stat(clf.OpenSSHKeysPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, trace.Wrap(err)
	}
	return true, nil
}

// openSSHInitialJoin
func (a *agentless) openSSHInitialJoin(ctx context.Context, clf config.CommandLineFlags) error {
	existing, err := a.existingKeysPresent(clf)
	if err != nil {
		return trace.Wrap(err)
	}

	privateKey, sshPublicKey, tlsPublicKey, err := GenerateKeys()
	if err != nil {
		return trace.Wrap(err, "unable to generate new keypairs")
	}

	var client auth.ClientI
	var certs *proto.Certs

	if existing {
		exPrivateKey, _, _, exCerts, err := ReadKeys(clf)
		if err != nil {
			return trace.Wrap(err)
		}
		identity, err := auth.ReadIdentityFromKeyPair(exPrivateKey, exCerts)
		if err != nil {
			return trace.Wrap(err)
		}

		// todo(amk): if this or generate host certs fails, should we try to blowaway /etc/teleport/agentless and start from scratch in else section?
		client, err = authenticatedUserClientFromIdentity(ctx, clf.InsecureMode, clf.FIPS, *a.proxyAddr, identity)
		if err != nil {
			return trace.Wrap(err)
		}
		defer client.Close()
		certs, err = client.GenerateHostCerts(ctx, &proto.HostCertsRequest{
			HostID:               a.uuid,
			NodeName:             a.hostname,
			Role:                 types.RoleNode,
			AdditionalPrincipals: a.principals,
			PublicTLSKey:         tlsPublicKey,
			PublicSSHKey:         sshPublicKey,
		})
		if err != nil {
			return trace.Wrap(err)
		}
	} else {
		certs, err = a.register(clf, sshPublicKey, tlsPublicKey)
		if err != nil {
			return trace.Wrap(err)
		}

		identity, err := auth.ReadIdentityFromKeyPair(privateKey, certs)
		if err != nil {
			return trace.Wrap(err)
		}

		client, err = authenticatedUserClientFromIdentity(ctx, clf.InsecureMode, clf.FIPS, *a.proxyAddr, identity)
		if err != nil {
			return trace.Wrap(err)
		}
		defer client.Close()
	}

	openSSHCA, err := a.getOpenSSHCA(ctx, client)
	if err != nil {
		return trace.Wrap(err)
	}

	hostSSHCA, hostTLSCA, err := a.getHostCA(ctx, client)
	if err != nil {
		return trace.Wrap(err)
	}

	err = a.updateKeysAndConfig(ctx, clf, agentlessKeys{
		privateKey: privateKey,
		certs:      certs,
		openSSHCA:  openSSHCA,
		hostSSHCA:  hostSSHCA,
		hostTLSCA:  hostTLSCA,
	})
	if err != nil {
		return trace.Wrap(err)
	}

	if clf.RestartOpenSSH {
		fmt.Println("Restarting the OpenSSH daemon")
		if err := a.restartSSHD(); err != nil {
			return trace.Wrap(err)
		}
	}

	fmt.Println("Attempting to register node")
	server, err := types.NewServer(a.uuid, types.KindNode, types.ServerSpecV2{
		Addr:     a.instanceAddr,
		Hostname: a.hostname,
		Rotation: types.Rotation{
			LastRotated: a.clock.Now(),
			Phase:       types.RotationPhaseStandby,
		},
	})
	if err != nil {
		return trace.Wrap(err)
	}
	server.SetSubKind("openssh")
	server.SetStaticLabels(map[string]string{
		types.AWSAccountIDLabel:  a.accountID,
		types.AWSInstanceIDLabel: a.instanceID,
		types.AWSInstanceRegion:  a.region,
	})

	if _, err := client.UpsertNode(ctx, server); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (a *agentless) openSSHRotateStageRollback(ctx context.Context, clf config.CommandLineFlags) error {
	if err := os.RemoveAll(clf.OpenSSHKeysPath); err != nil {
		return trace.Wrap(err)
	}

	// move the old keys to the backup directory
	if err := os.Rename(clf.OpenSSHKeysBackupPath, clf.OpenSSHKeysPath); err != nil {
		return trace.Wrap(err)
	}

	exPrivateKey, _, _, exCerts, err := ReadKeys(clf)
	if err != nil {
		return trace.Wrap(err)
	}
	identity, err := auth.ReadIdentityFromKeyPair(exPrivateKey, exCerts)
	if err != nil {
		return trace.Wrap(err)
	}

	// todo(amk): if this or generate host certs fails, should we try to blowaway /etc/teleport/agentless and start from scratch in else section?
	client, err := authenticatedUserClientFromIdentity(ctx, clf.InsecureMode, clf.FIPS, *a.proxyAddr, identity)
	if err != nil {
		return trace.Wrap(err)
	}

	server, err := types.NewServer(a.uuid, types.KindNode, types.ServerSpecV2{
		Addr:     a.instanceAddr,
		Hostname: a.hostname,
		Rotation: types.Rotation{
			LastRotated: a.clock.Now(),
			Phase:       types.RotationPhaseStandby,
		},
	})
	if err != nil {
		return trace.Wrap(err)
	}
	server.SetSubKind("openssh")
	server.SetStaticLabels(map[string]string{
		types.AWSAccountIDLabel:  a.accountID,
		types.AWSInstanceIDLabel: a.instanceID,
		types.AWSInstanceRegion:  a.region,
	})

	if _, err := client.UpsertNode(ctx, server); err != nil {
		return trace.Wrap(err)
	}

	if err := a.restartSSHD(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func checkSSHDConfigAlreadyUpdated(sshdConfigPath, fileContains string) (bool, error) {
	contents, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return false, trace.Wrap(err)
	}
	return !strings.Contains(string(contents), fileContains), nil
}

func prefixSSHDConfig(sshdConfigPath, config string) error {
	contents, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return trace.Wrap(err)
	}
	line := append([]byte(config), byte('\n'))
	contents = append(line, contents...)

	err = os.WriteFile(sshdConfigPath, contents, 0644)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func fmtSSHDConfigUpdate(openSSHCAPath string, hostKeyPaths, hostCertPaths []string) string {
	return fmt.Sprintf(`
%s
TrustedUserCaKeys %s
HostKey %s
HostCertificate %s
`,
		sshdConfigSectionModificationHeader,
		openSSHCAPath,
		strings.Join(hostKeyPaths, " "),
		strings.Join(hostCertPaths, " "),
	)
}

func updateSSHDConfig(sshdConfigPath, teleportSSHDConfigPath, opensshCAPath string,
	hostKeys, hostCerts []string) error {
	needsUpdate, err := checkSSHDConfigAlreadyUpdated(sshdConfigPath, agentlessSSHDConfigInclude)
	if err != nil {
		return trace.Wrap(err)
	}
	if needsUpdate {
		if err := prefixSSHDConfig(sshdConfigPath, agentlessSSHDConfigInclude); err != nil {
			return trace.Wrap(err)
		}
	}

	configUpdate := fmtSSHDConfigUpdate(
		opensshCAPath,
		hostKeys,
		hostCerts,
	)

	sshdConfigTmp, err := os.CreateTemp("", "")
	if err != nil {
		return trace.Wrap(err)
	}
	defer sshdConfigTmp.Close()
	if _, err := sshdConfigTmp.Write([]byte(configUpdate)); err != nil {
		return trace.Wrap(err)
	}

	if err := sshdConfigTmp.Sync(); err != nil {
		return trace.Wrap(err)
	}

	cmd := exec.Command(sshdBinary, "-t", "-f", sshdConfigTmp.Name())
	if err := cmd.Run(); err != nil {
		return trace.Wrap(err, "teleport generated an invalid ssh config file, not writing")
	}

	if err := os.Rename(sshdConfigTmp.Name(), teleportSSHDConfigPath); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func restartSSHD() error {
	cmd := exec.Command("sshd", "-t")
	if err := cmd.Run(); err != nil {
		return trace.Wrap(err, "teleport generated an invalid ssh config file")
	}

	cmd = exec.Command("systemctl", "restart", "sshd")
	if err := cmd.Run(); err != nil {
		return trace.Wrap(err, "teleport failed to restart the sshd service")
	}
	return nil
}
