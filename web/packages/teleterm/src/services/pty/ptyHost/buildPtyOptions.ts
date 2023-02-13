/**
 * Copyright 2023 Gravitational, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import path, { delimiter } from 'path';

import { RuntimeSettings } from 'teleterm/mainProcess/types';
import { PtyProcessOptions } from 'teleterm/sharedProcess/ptyHost';

import {
  PtyCommand,
  PtyProcessCreationStatus,
  TshKubeLoginCommand,
} from '../types';

import {
  resolveShellEnvCached,
  ResolveShellEnvTimeoutError,
} from './resolveShellEnv';

export async function buildPtyOptions(
  settings: RuntimeSettings,
  cmd: PtyCommand
): Promise<{
  processOptions: PtyProcessOptions;
  creationStatus: PtyProcessCreationStatus;
}> {
  return resolveShellEnvCached(settings.defaultShell)
    .then(resolvedEnv => ({
      shellEnv: resolvedEnv,
      creationStatus: PtyProcessCreationStatus.Ok,
    }))
    .catch(error => {
      if (error instanceof ResolveShellEnvTimeoutError) {
        return {
          shellEnv: undefined,
          creationStatus: PtyProcessCreationStatus.ResolveShellEnvTimeout,
        };
      }
      throw error;
    })
    .then(({ shellEnv, creationStatus }) => {
      const combinedEnv = {
        ...process.env,
        ...shellEnv,
        TELEPORT_HOME: settings.tshd.homeDir,
        TELEPORT_CLUSTER: cmd.clusterName,
        TELEPORT_PROXY: cmd.proxyHost,
      };

      return {
        processOptions: getPtyProcessOptions(settings, cmd, combinedEnv),
        creationStatus,
      };
    });
}

function getPtyProcessOptions(
  settings: RuntimeSettings,
  cmd: PtyCommand,
  env: typeof process.env
): PtyProcessOptions {
  switch (cmd.kind) {
    case 'pty.shell':
      // Teleport Connect bundles a tsh binary, but the user might have one already on their system.
      // Since we use our own TELEPORT_HOME which might differ in format with the version that the
      // user has installed, let's prepend our bin directory to PATH.
      //
      // At the moment, this won't ensure that our bin dir is at the front of the path. When the
      // shell session starts, the shell will read the rc files. This means that if the user
      // prepends the path there, they can possibly have different version of tsh there.
      //
      // settings.binDir is present only in the packaged version of the app.
      if (settings.binDir) {
        prependBinDirToPath(env, settings);
      }

      return {
        path: settings.defaultShell,
        args: [],
        cwd: cmd.cwd,
        env,
        initCommand: cmd.initCommand,
      };

    case 'pty.tsh-kube-login': {
      const isWindows = settings.platform === 'win32';

      // backtick (PowerShell) and backslash (Bash) are used to escape a whitespace
      const escapedBinaryPath = settings.tshd.binaryPath.replaceAll(
        ' ',
        isWindows ? '` ' : '\\ '
      );
      const kubeLoginCommand = [
        escapedBinaryPath,
        `--proxy=${cmd.rootClusterId}`,
        `kube login ${cmd.kubeId} --cluster=${cmd.clusterName}`,
        settings.tshd.insecure && '--insecure',
      ]
        .filter(Boolean)
        .join(' ');
      const bashCommandArgs = ['-c', `${kubeLoginCommand};$SHELL`];
      const powershellCommandArgs = ['-NoExit', '-c', kubeLoginCommand];
      return {
        path: settings.defaultShell,
        args: isWindows ? powershellCommandArgs : bashCommandArgs,
        env: { ...env, KUBECONFIG: getKubeConfigFilePath(cmd, settings) },
      };
    }

    case 'pty.tsh-login':
      const loginHost = cmd.login
        ? `${cmd.login}@${cmd.serverId}`
        : cmd.serverId;

      return {
        path: settings.tshd.binaryPath,
        args: [
          `--proxy=${cmd.rootClusterId}`,
          'ssh',
          '--forward-agent',
          loginHost,
        ],
        env,
      };
    default:
      throw Error(`Unknown pty command: ${cmd}`);
  }
}

function prependBinDirToPath(
  env: typeof process.env,
  settings: RuntimeSettings
): void {
  const pathName = settings.platform === 'win32' ? 'Path' : 'PATH';
  env[pathName] = [settings.binDir, env[pathName]]
    .map(path => path?.trim())
    .filter(Boolean)
    .join(delimiter);
}

function getKubeConfigFilePath(
  command: TshKubeLoginCommand,
  settings: RuntimeSettings
): string {
  return path.join(settings.kubeConfigsDir, command.kubeConfigRelativePath);
}
