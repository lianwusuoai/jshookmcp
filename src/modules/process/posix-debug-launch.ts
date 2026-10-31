/**
 * Shared POSIX debug-launch implementation for LinuxProcessManager /
 * MacProcessManager.
 *
 * The two platform managers previously carried byte-identical 60-line
 * launchWithDebug bodies (fallow clone dup). Platform differences live in the
 * callers' getProcessByPid, which this helper receives as a callback.
 */
import { spawn } from 'node:child_process';
import { logger } from '@utils/logger';
import { DEFAULT_DEBUG_PORT, PROCESS_LAUNCH_WAIT_MS } from '@src/constants';
import { buildChromiumDebugLaunch } from '@modules/process/chromium-launch';
import { ProcessRegistry } from '@utils/ProcessRegistry';
import type { ProcessInfo } from '@modules/process/ProcessManager.types';

export async function launchWithDebugPosix(
  executablePath: string,
  getProcessByPid: (pid: number) => Promise<ProcessInfo | null>,
  debugPort: number = DEFAULT_DEBUG_PORT,
  args: string[] = [],
): Promise<ProcessInfo | null> {
  try {
    const plan = buildChromiumDebugLaunch(executablePath, debugPort, args);

    const child = spawn(executablePath, plan.debugArgs, {
      detached: true,
      stdio: 'ignore',
    });

    child.unref();
    ProcessRegistry.register(child);

    await new Promise((resolve) => setTimeout(resolve, PROCESS_LAUNCH_WAIT_MS));

    if (!child.pid) {
      logger.error(`Failed to spawn process: PID is undefined for ${executablePath}`);
      return null;
    }
    // Fast-fail (issue #206): a target that died immediately must not be
    // reported as a live debuggable process.
    if (typeof child.exitCode === 'number' || typeof child.signalCode === 'string') {
      logger.error(`Debug launch target exited immediately: ${executablePath}`, {
        exitCode: child.exitCode,
        signalCode: child.signalCode,
      });
      return null;
    }
    const process = await getProcessByPid(child.pid);

    logger.info(`Launched process with debug port ${debugPort}:`, {
      pid: child.pid,
      executable: executablePath,
    });

    return process;
  } catch (error) {
    logger.error('Failed to launch process with debug:', error);
    return null;
  }
}
