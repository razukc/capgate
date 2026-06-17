// bwrap adapter: NormalizedPolicy → bubblewrap argv + companion artifacts.
//
// bwrap (bubblewrap) is a Linux user-namespace sandbox. It handles:
//   - filesystem bind mounts (--bind / --ro-bind)
//   - process/IPC/net namespace toggles (--unshare-*)
//   - env var pruning (--clearenv + explicit --setenv)
//
// It does NOT handle:
//   - host-level network allowlisting  → EgressRule[] (companion proxy)
//   - seccomp syscall filters          → out of scope for v0.1
//   - secret value resolution          → caller pulls from secret store
//
// Net posture (fail-closed). bwrap's --unshare-net is all-or-nothing: an
// unprivileged user namespace cannot mint veth pairs or routes, so bwrap can
// only fully isolate the net namespace or fully share the host's. Selective
// egress is impossible inside bwrap alone. Therefore this adapter ALWAYS emits
// --unshare-net — even when egress is declared — and NEVER shares the host
// netns. A declared net capability does not relax isolation; it only records an
// EgressRule[] that a privileged broker must honor by launching the bwrap
// process inside a pre-created, egress-constrained network namespace. If no
// such broker exists, the sandbox simply has no network: deny-by-default holds.
// (The prior behavior — sharing host netns whenever net>0 — was a silent
// privilege escalation that read as a constraint; it is refused by design.)
//
// This adapter emits a BwrapArtifact: argv for bwrap itself plus companion
// data the host must honor. The host decides how to wire EgressRule — mitmproxy,
// nftables, Envoy; the adapter stays policy-layer only.

import { NormalizedPolicy } from '../ir.js';
import type { Provenance } from '../provenance.js';

export interface BwrapArtifact {
  /** argv, ready for execFile("bwrap", argv). Binary and command are appended by caller. */
  argv: string[];
  /** Network egress rules. Empty = no net allowed. */
  egress: EgressRule[];
  /** Env vars the host must inject (names only; values resolved out-of-band). */
  envInjections: string[];
  /** Declared assertions — emitted as metadata, not enforced here. */
  assertions: { id: string; description: string }[];
  /** Binds this artifact to the capability manifest it was compiled from. Present when compiled via compile(). */
  provenance?: Provenance;
  /** Human-readable diagnostics for audit logs / PR review. */
  notes: string[];
}

export interface EgressRule {
  host: string;
  port: number | null;
  blockPrivate: boolean;
}

export interface BwrapOptions {
  /** Base read-only system mounts. Defaults cover the common Linux userspace. */
  systemMounts?: string[];
  /** Whether to expose /dev (true when nestedSandbox, false otherwise). */
  exposeDev?: boolean;
}

const DEFAULT_SYSTEM_MOUNTS = ['/usr', '/lib', '/lib64', '/bin', '/sbin', '/etc/ssl', '/etc/ca-certificates'];

export function lowerToBwrap(policy: NormalizedPolicy, opts: BwrapOptions = {}): BwrapArtifact {
  const argv: string[] = [];
  const notes: string[] = [];
  const systemMounts = opts.systemMounts ?? DEFAULT_SYSTEM_MOUNTS;
  const exposeDev = opts.exposeDev ?? policy.nestedSandbox;

  // ---------- base namespaces ----------
  // We build the unshare set explicitly instead of using --unshare-all so each
  // namespace is an auditable decision point. Net is ALWAYS unshared: bwrap
  // cannot do selective egress (see header), so sharing the host netns would be
  // a silent grant of full host network access. Declared egress is carried in
  // egress[] for an external netns broker to enforce, never by relaxing this.
  // nestedSandbox additionally keeps user/pid/ipc for inner sandboxes
  // (Chromium, QEMU) that re-namespace themselves.
  argv.push('--unshare-uts', '--unshare-cgroup-try', '--unshare-net');
  if (!policy.nestedSandbox) {
    argv.push('--unshare-user-try', '--unshare-pid', '--unshare-ipc');
  } else {
    notes.push('nestedSandbox: keeping user/pid/ipc namespaces for inner sandbox compatibility');
  }
  argv.push('--die-with-parent', '--new-session');

  // ---------- system mounts ----------
  for (const m of systemMounts) {
    argv.push('--ro-bind-try', m, m);
  }
  argv.push('--proc', '/proc');
  // Only emit tmpfs /tmp if no declared fs root covers /tmp. A real bind on
  // /tmp implies the tool needs persistent host files there (e.g. X11 socket,
  // browser downloads dir); a tmpfs would either shadow the bind or race it.
  const tmpCovered = policy.fs.some((fs) => {
    const host = dirForBind(fs.path);
    return host === '/tmp' || host.startsWith('/tmp/');
  });
  if (!tmpCovered) argv.push('--tmpfs', '/tmp');
  if (exposeDev) argv.push('--dev', '/dev');

  // ---------- clock ----------
  if (policy.clock === 'tzdata') {
    argv.push('--ro-bind-try', '/usr/share/zoneinfo', '/usr/share/zoneinfo');
    argv.push('--ro-bind-try', '/etc/localtime', '/etc/localtime');
  }

  // ---------- fs roots ----------
  for (const fs of policy.fs) {
    const hostPath = dirForBind(fs.path);
    const writable = fs.actions.includes('write') || fs.actions.includes('create') || fs.actions.includes('delete');
    argv.push(writable ? '--bind' : '--ro-bind', hostPath, hostPath);
    if (fs.isGlob) {
      notes.push(
        `fs: "${fs.path}" lowered to directory bind "${hostPath}" — bwrap binds directories, not globs. Fine-grained glob enforcement is the server's job.`
      );
    }
    if (hostPath === '/tmp') {
      notes.push(
        'fs: binding host /tmp exposes all user tmpfiles to the sandbox; prefer a scoped subdirectory like /tmp/<server-name>.'
      );
    }
  }

  // ---------- exec binaries ----------
  // No extra mounts needed — covered by /usr /bin /sbin above. We record the
  // declaration for audit and warn if an unusual binary was requested.
  for (const e of policy.exec) {
    notes.push(`exec: ${e.binary} (resolved from PATH inside sandbox)`);
  }

  // ---------- env (declared first so ipc handlers can push injections) ----------
  const envInjections: string[] = [];
  for (const e of policy.env) envInjections.push(e.name);

  // ---------- ipc ----------
  for (const i of policy.ipc) {
    if (i.endpoint === 'x11') {
      argv.push('--bind-try', '/tmp/.X11-unix', '/tmp/.X11-unix');
      // DISPLAY is resolved by the host at exec time; we record the need.
      envInjections.push('DISPLAY');
    } else if (i.endpoint.startsWith('unix:')) {
      const sock = i.endpoint.slice('unix:'.length);
      argv.push('--bind-try', sock, sock);
    } else if (i.endpoint === 'dbus:session') {
      notes.push('ipc: dbus:session declared — host must bind DBUS_SESSION_BUS_ADDRESS socket');
    } else if (i.endpoint === 'dbus:system') {
      argv.push('--bind-try', '/run/dbus/system_bus_socket', '/run/dbus/system_bus_socket');
    } else {
      notes.push(`ipc: unrecognized endpoint "${i.endpoint}" — no mount emitted`);
    }
  }

  // ---------- env ----------
  argv.push('--clearenv');
  // Always preserve a minimal safe floor.
  argv.push('--setenv', 'PATH', '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin');
  argv.push('--setenv', 'HOME', '/tmp');
  // Values for envInjections are injected by the caller via --setenv at exec time.

  // ---------- net ----------
  // The net namespace is already unshared above, so the sandbox starts with NO
  // network (loopback only). bwrap cannot open a constrained hole, so declared
  // egress is NOT enforced here: we emit EgressRule[] for a privileged broker
  // that runs this bwrap process inside a pre-created, egress-aware netns. We
  // emit rules even for the empty case so a deny-all broker is a valid host.
  const egress: EgressRule[] = policy.net.map((n) => ({
    host: n.host,
    port: n.port,
    blockPrivate: n.blockPrivate,
  }));
  if (policy.net.length > 0) {
    notes.push(
      `net: ${policy.net.length} endpoint(s) declared but NOT enforced by bwrap alone — bwrap always unshares the net namespace (no host network). To grant egress, a privileged broker MUST launch bwrap inside a pre-created network namespace whose egress honors egress[]. Absent that broker the sandbox has no network. Sharing the host netns is refused by design.`
    );
  }

  return {
    argv,
    egress,
    envInjections,
    assertions: policy.assertions.map((a) => ({ id: a.id, description: a.description })),
    ...(policy.provenance ? { provenance: policy.provenance } : {}),
    notes,
  };
}

/**
 * Return the directory portion bwrap should bind. For a glob like
 * "/workspace/**" we bind "/workspace". For a bare file we bind the parent.
 * bwrap binds directories; file-granularity is out of scope.
 */
function dirForBind(path: string): string {
  const stripped = path.replace(/\/\*\*?$/, '').replace(/\/\*$/, '');
  if (stripped.endsWith('/')) return stripped.slice(0, -1) || '/';
  // If the path looks like a file (has an extension after the last slash), bind parent.
  const lastSlash = stripped.lastIndexOf('/');
  const tail = stripped.slice(lastSlash + 1);
  if (tail.includes('.') && !tail.startsWith('.')) {
    return stripped.slice(0, lastSlash) || '/';
  }
  return stripped || '/';
}
