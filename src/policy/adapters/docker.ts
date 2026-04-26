// Docker adapter: NormalizedPolicy → `docker run` argv + companion artifacts.
//
// Scope parallel to bwrap: emit flags, not images or commands. The host
// appends the image reference and entrypoint args. The host also chooses
// which network to attach to (or none) — this adapter only signals that an
// egress-aware network is required when policy.net is non-empty.
//
// What Docker handles natively:
//   - filesystem bind mounts (--volume :ro / :rw)
//   - network isolation (--network none)
//   - env injection (--env)
//   - capability scrub (--cap-drop=ALL, --security-opt=no-new-privileges)
//
// What Docker does NOT handle here:
//   - host-level egress allowlisting → EgressRule[] (companion proxy)
//   - seccomp customization beyond default → out of scope for v0.1
//   - secret value resolution → caller pulls from a secret store
//   - inner Chromium-style sandboxes → surfaced as a note; host decides whether
//     to add SYS_ADMIN, run unprivileged Chromium with --no-sandbox (insecure!),
//     or mount /proc differently. This adapter refuses to silently elevate.

import { NormalizedPolicy } from '../ir.js';
import type { EgressRule } from './bwrap.js';

export interface DockerArtifact {
  /** argv, ready for execFile("docker", ["run", ...argv, image, ...cmd]). */
  argv: string[];
  /** Network egress rules. Empty = no net allowed (host SHOULD use --network none). */
  egress: EgressRule[];
  /** Env vars the host must inject (names only; values resolved out-of-band). */
  envInjections: string[];
  /** Declared assertions — emitted as metadata, not enforced here. */
  assertions: { id: string; description: string }[];
  /** Human-readable diagnostics for audit logs / PR review. */
  notes: string[];
}

export interface DockerOptions {
  /**
   * Whether to emit `--read-only` on the root filesystem. Default true.
   * Disable only if your image cannot run with a read-only rootfs (rare).
   */
  readOnlyRootfs?: boolean;
  /**
   * Optional user to run as inside the container, e.g. "1000:1000". Default
   * unset (image-defined). Recommended in production; left unset here so the
   * adapter's output is portable across images.
   */
  user?: string;
}

const SAFE_DEFAULTS = {
  readOnlyRootfs: true as boolean,
};

export function lowerToDocker(policy: NormalizedPolicy, opts: DockerOptions = {}): DockerArtifact {
  const argv: string[] = [];
  const notes: string[] = [];
  const readOnlyRootfs = opts.readOnlyRootfs ?? SAFE_DEFAULTS.readOnlyRootfs;

  // ---------- baseline hardening ----------
  argv.push('--rm');
  argv.push('--cap-drop', 'ALL');
  argv.push('--security-opt', 'no-new-privileges');
  if (readOnlyRootfs) argv.push('--read-only');
  // Tmpfs for /tmp unless a declared fs root covers it (mirror of bwrap logic).
  const tmpCovered = policy.fs.some((fs) => {
    const host = dirForBind(fs.path);
    return host === '/tmp' || host.startsWith('/tmp/');
  });
  if (!tmpCovered) argv.push('--tmpfs', '/tmp');
  if (opts.user) argv.push('--user', opts.user);

  // ---------- network ----------
  // bwrap is binary-share. Docker has the same shape: --network none vs
  // attach-to-an-egress-aware-network. We emit the deny case directly and
  // signal the allow case via a note — choosing the network name is host policy.
  if (policy.net.length === 0) {
    argv.push('--network', 'none');
  } else {
    notes.push(
      `net: ${policy.net.length} endpoint(s) declared — host MUST attach the container to a network whose egress honors egress[]; do NOT use --network host`
    );
  }

  // ---------- fs binds ----------
  for (const fs of policy.fs) {
    const hostPath = dirForBind(fs.path);
    const writable = fs.actions.includes('write') || fs.actions.includes('create') || fs.actions.includes('delete');
    argv.push('--volume', `${hostPath}:${hostPath}:${writable ? 'rw' : 'ro'}`);
    if (fs.isGlob) {
      notes.push(
        `fs: "${fs.path}" lowered to volume mount "${hostPath}" — Docker mounts directories, not globs. Fine-grained glob enforcement is the server's job.`
      );
    }
    if (hostPath === '/tmp') {
      notes.push(
        'fs: mounting host /tmp exposes all user tmpfiles to the container; prefer a scoped subdirectory like /tmp/<server-name>.'
      );
    }
  }

  // ---------- clock ----------
  if (policy.clock === 'tzdata') {
    argv.push('--volume', '/usr/share/zoneinfo:/usr/share/zoneinfo:ro');
    argv.push('--volume', '/etc/localtime:/etc/localtime:ro');
  }

  // ---------- exec binaries ----------
  // No mounts to add — the image is responsible for shipping the binary.
  // We surface the declaration so a reviewer can verify the image actually
  // contains it (catches image/manifest drift).
  for (const e of policy.exec) {
    notes.push(`exec: ${e.binary} (must be present in the chosen image)`);
  }

  // ---------- env (declared first so ipc handlers can push injections) ----------
  const envInjections: string[] = [];
  for (const e of policy.env) envInjections.push(e.name);

  // ---------- ipc ----------
  for (const i of policy.ipc) {
    if (i.endpoint === 'x11') {
      argv.push('--volume', '/tmp/.X11-unix:/tmp/.X11-unix:ro');
      envInjections.push('DISPLAY');
    } else if (i.endpoint.startsWith('unix:')) {
      const sock = i.endpoint.slice('unix:'.length);
      argv.push('--volume', `${sock}:${sock}`);
    } else if (i.endpoint === 'dbus:session') {
      notes.push('ipc: dbus:session declared — host must mount DBUS_SESSION_BUS_ADDRESS socket');
    } else if (i.endpoint === 'dbus:system') {
      argv.push('--volume', '/run/dbus/system_bus_socket:/run/dbus/system_bus_socket');
    } else {
      notes.push(`ipc: unrecognized endpoint "${i.endpoint}" — no mount emitted`);
    }
  }

  // ---------- nestedSandbox ----------
  // Chromium and friends fight container isolation similarly to namespaces.
  // We surface the conflict explicitly rather than auto-adding SYS_ADMIN or
  // --privileged. The host knows whether it's running a trusted image.
  if (policy.nestedSandbox) {
    notes.push(
      'nestedSandbox: declared — Docker default seccomp + dropped capabilities may break inner sandboxes (e.g. Chromium). Host MUST decide between (a) running the inner tool with its own sandbox disabled (insecure), (b) granting SYS_ADMIN + a tailored seccomp profile, or (c) using a microVM adapter (Firecracker) instead. capgate refuses to choose for you.'
    );
  }

  // ---------- env injections (emit names; values are caller's job) ----------
  for (const name of envInjections) {
    argv.push('--env', name);
  }

  // ---------- egress ----------
  const egress: EgressRule[] = policy.net.map((n) => ({
    host: n.host,
    port: n.port,
    blockPrivate: n.blockPrivate,
  }));

  return {
    argv,
    egress,
    envInjections,
    assertions: policy.assertions.map((a) => ({ id: a.id, description: a.description })),
    notes,
  };
}

/**
 * Return the directory portion Docker should bind. Mirrors bwrap's logic
 * exactly so the two adapters agree on host-path scope. Kept duplicated (not
 * shared) intentionally: if one adapter ever needs different glob semantics,
 * we want that divergence to be a deliberate edit, not a shared-helper surprise.
 */
function dirForBind(path: string): string {
  const stripped = path.replace(/\/\*\*?$/, '').replace(/\/\*$/, '');
  if (stripped.endsWith('/')) return stripped.slice(0, -1) || '/';
  const lastSlash = stripped.lastIndexOf('/');
  const tail = stripped.slice(lastSlash + 1);
  if (tail.includes('.') && !tail.startsWith('.')) {
    return stripped.slice(0, lastSlash) || '/';
  }
  return stripped || '/';
}
