import { common, Want } from '@kit.AbilityKit';
import { vpnExtension } from '@kit.NetworkKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { LocalRpc, RpcError } from './LocalRpc';
import {
  normalizeConfig,
  Conn,
  ConnParams,
  DelayParams,
  DelayResult,
  DeleteParams,
  EmptyParams,
  GroupStatus,
  ImportParams,
  ImportResult,
  LogsParams,
  LogsResult,
  ModeParams,
  NodeStatus,
  SelectParams,
  SetConfigParams,
  StartParams,
  Status,
  SubParams,
  SubUpdateParams,
  VeilConfig,
  VersionResult
} from '../model/Types';

const TAG = 'VeilCore';

/** Liveness of the socket to the core, as observed by the UI. */
export enum CoreState {
  Idle = 0,
  Connecting = 1,
  Ready = 2,
  Unavailable = 3
}

const SOCKET_NAME = '/veil.sock';
const HOST_ABILITY = 'VeilVpnAbility';
const RECONNECT_TRIES = 20;
const RECONNECT_DELAY_MS = 250;

/**
 * CoreClient — the UI process' only door to the engine.
 *
 * The UI never loads libveil.so. The Go core lives in the VPN extension
 * process, listens on <filesDir>/veil.sock, and this class is a thin typed
 * wrapper around that socket. Every method throws RpcError with the core's own
 * error text, so callers can show the truth instead of a generic failure.
 */
export class CoreClient {
  private static instance: CoreClient | null = null;

  private rpc: LocalRpc = new LocalRpc();
  private filesDir: string = '';
  private bundleName: string = 'com.nolanho.kitsune';
  private state: CoreState = CoreState.Idle;
  private lastError: string = '';
  private bootInFlight: Promise<boolean> | null = null;
  private recovering: boolean = false;
  private stateSubs: ((s: CoreState) => void)[] = [];
  private ctx: common.UIAbilityContext | null = null;

  static get(): CoreClient {
    if (CoreClient.instance === null) {
      CoreClient.instance = new CoreClient();
    }
    return CoreClient.instance;
  }

  init(ctx: common.UIAbilityContext): void {
    this.ctx = ctx;
    this.filesDir = ctx.filesDir;
    this.bundleName = ctx.abilityInfo.bundleName;
    this.rpc.onClose((reason: string) => {
      this.lastError = reason;
      this.setState(CoreState.Unavailable);
    });
  }

  /** The UI ability context; needed for cross-process Preferences access. */
  abilityContext(): common.UIAbilityContext | null {
    return this.ctx;
  }

  getState(): CoreState {
    return this.state;
  }

  getLastError(): string {
    return this.lastError;
  }

  socketPath(): string {
    return this.filesDir + SOCKET_NAME;
  }

  onState(listener: (s: CoreState) => void): void {
    this.stateSubs.push(listener);
  }

  offState(listener: (s: CoreState) => void): void {
    const idx: number = this.stateSubs.indexOf(listener);
    if (idx >= 0) {
      this.stateSubs.splice(idx, 1);
    }
  }

  /**
   * Makes sure the host (VPN extension) is up and we are connected to it.
   * Returns true when the socket is usable. Never lies: on failure the state
   * stays Unavailable and lastError carries the reason.
   *
   * Concurrent callers (EntryAbility.onForeground racing the first page paint)
   * share one in-flight attempt — two socket handshakes would close each
   * other's LocalSocket.
   */
  async bootstrap(): Promise<boolean> {
    if (this.state === CoreState.Ready && this.rpc.isOpen()) {
      return true;
    }
    if (this.bootInFlight !== null) {
      return this.bootInFlight;
    }
    this.bootInFlight = this.bootstrapInner();
    const ok: boolean = await this.bootInFlight;
    this.bootInFlight = null;
    return ok;
  }

  private async bootstrapInner(): Promise<boolean> {
    this.setState(CoreState.Connecting);
    this.lastError = '';

    const want: Want = { bundleName: this.bundleName, abilityName: HOST_ABILITY };
    try {
      await vpnExtension.startVpnExtensionAbility(want);
    } catch (err) {
      const be: BusinessError = err as BusinessError;
      // 16000002 = wrong ability type, 16000001 = missing; anything here means
      // the host cannot be started, but it may still be alive from a previous
      // session, so we try the socket anyway.
      hilog.warn(0x0000, TAG, 'startVpnExtensionAbility failed: %{public}s', be.message);
      this.lastError = '启动 VPN 扩展失败: ' + be.message;
    }

    const path: string = this.socketPath();
    for (let attempt = 0; attempt < RECONNECT_TRIES; attempt++) {
      try {
        await this.rpc.connect(path, 1500);
        // Probe with the raw transport: calling status() would recurse into
        // call() → bootstrap() while bootstrap is still in flight.
        const st: Status = await this.rpc.request('status', emptyParams()) as Status;
        this.setState(CoreState.Ready);
        this.lastError = '';
        hilog.info(0x0000, TAG, 'core ready, phase=%{public}s', st.phase);
        return true;
      } catch (err) {
        if (attempt === RECONNECT_TRIES - 1) {
          const re: RpcError = err as RpcError;
          this.lastError = re.message;
        }
      }
      await sleep(RECONNECT_DELAY_MS);
    }
    this.setState(CoreState.Unavailable);
    return false;
  }

  /** Reconnect without restarting the extension (used by the "重试" button). */
  async reconnect(): Promise<boolean> {
    this.rpc.close();
    this.setState(CoreState.Connecting);
    const path: string = this.socketPath();
    for (let attempt = 0; attempt < RECONNECT_TRIES; attempt++) {
      try {
        await this.rpc.connect(path, 1500);
        this.setState(CoreState.Ready);
        this.lastError = '';
        return true;
      } catch (err) {
        this.lastError = (err as RpcError).message;
      }
      await sleep(RECONNECT_DELAY_MS);
    }
    this.setState(CoreState.Unavailable);
    return false;
  }

  shutdown(): void {
    this.rpc.close();
    this.setState(CoreState.Unavailable);
  }

  private setState(s: CoreState): void {
    if (this.state === s) {
      return;
    }
    this.state = s;
    for (let i = 0; i < this.stateSubs.length; i++) {
      this.stateSubs[i](s);
    }
  }

  // -- typed façade ---------------------------------------------------------
  // Casts only happen here: the socket hands back Object, we hand back a type.

  /**
   * One RPC, with self-healing.
   *
   * The core lives in the VPN extension process, and HarmonyOS reaps an idle
   * extension (log: "VeilVpnAbility inactive timeout").

   * Without this retry the UI would sit on "本地套接字已关闭" until the user
   * tapped 重试 — so a failed call re-creates the host and retries exactly once.
   */
  private async call(method: string, params: Object): Promise<Object> {
    if (this.recovering) {
      return this.rpc.request(method, params);
    }
    try {
      return await this.rpc.request(method, params);
    } catch (err) {
      this.recovering = true;
      this.rpc.close();
      const ok: boolean = await this.bootstrap();
      this.recovering = false;
      if (!ok) {
        throw err as Error;
      }
      return await this.rpc.request(method, params);
    }
  }

  async status(): Promise<Status> {
    const r: Object = await this.call('status', emptyParams());
    return r as Status;
  }

  async groups(): Promise<GroupStatus[]> {
    const r: Object = await this.call('groups', emptyParams());
    return r as GroupStatus[];
  }

  async nodes(): Promise<NodeStatus[]> {
    const r: Object = await this.call('nodes', emptyParams());
    return r as NodeStatus[];
  }

  async config(): Promise<VeilConfig> {
    const r: Object = await this.call('config', emptyParams());
    // A nil Go slice arrives as JSON null; normalise before any view can
    // iterate it (that is what used to crash the 规则 tab).
    return normalizeConfig(r as VeilConfig);
  }

  async version(): Promise<VersionResult> {
    const r: Object = await this.call('version', emptyParams());
    return r as VersionResult;
  }

  async conns(): Promise<Conn[]> {
    const r: Object = await this.call('conns', emptyParams());
    return r as Conn[];
  }

  /**
   * `start`/`stop` return an unspecified result (rpc.go documents params only),
   * so we treat them as fire-and-verify: the caller re-polls `status`, which is
   * the single source of truth for phase.
   */
  async start(): Promise<void> {
    const p: StartParams = { tun_fd: -1 };
    await this.callT('start', p, 20000);
  }

  async stop(): Promise<void> {
    await this.callT('stop', emptyParams(), 20000);
  }

  async setMode(mode: string): Promise<Status> {
    const p: ModeParams = { mode: mode };
    const r: Object = await this.call('set_mode', p);
    return r as Status;
  }

  async select(group: string, tag: string): Promise<GroupStatus> {
    const p: SelectParams = { group: group, tag: tag };
    const r: Object = await this.call('select', p);
    return r as GroupStatus;
  }

  async delay(tag: string, timeoutMs: number = 3000): Promise<DelayResult> {
    const p: DelayParams = { tag: tag, timeout_ms: timeoutMs };
    const r: Object = await this.call('delay', p);
    return r as DelayResult;
  }

  async importText(text: string): Promise<ImportResult> {
    const p: ImportParams = { text: text };
    const r: Object = await this.callT('import', p, 30000);
    return r as ImportResult;
  }

  async deleteNode(tag: string): Promise<void> {
    const p: DeleteParams = { tag: tag };
    await this.call('delete', p);
  }

  async subAdd(name: string, url: string): Promise<void> {
    const p: SubParams = { name: name, url: url };
    await this.call('sub_add', p);
  }

  async subUpdate(name: string): Promise<NodeStatus[]> {
    const p: SubUpdateParams = { name: name };
    const r: Object = await this.callT('sub_update', p, 60000);
    return r as NodeStatus[];
  }

  async subDelete(name: string): Promise<void> {
    const p: SubUpdateParams = { name: name };
    await this.call('sub_delete', p);
  }

  async logs(afterId: number, limit: number = 200, level: string = ''): Promise<LogsResult> {
    const p: LogsParams = { after_id: afterId, limit: limit };
    if (level.length > 0) {
      p.level = level;
    }
    const r: Object = await this.call('logs', p);
    return r as LogsResult;
  }

  async setConfig(cfg: VeilConfig): Promise<Status> {
    const p: SetConfigParams = { config: cfg };
    const r: Object = await this.callT('set_config', p, 15000);
    return r as Status;
  }

  async resetStats(): Promise<void> {
    await this.call('reset_stats', emptyParams());
  }

  async closeConn(id: number): Promise<void> {
    const p: ConnParams = { id: id };
    await this.call('close_conn', p);
  }

  async closeAll(): Promise<void> {
    await this.call('close_all', emptyParams());
  }

  // `call` with a custom timeout, kept private to this class.
  private async callT(method: string, params: Object, timeoutMs: number): Promise<Object> {
    return this.rpc.request(method, params, timeoutMs);
  }
}

function emptyParams(): EmptyParams {
  const p: EmptyParams = {};
  return p;
}

function sleep(ms: number): Promise<void> {
  return new Promise<void>((resolve: () => void): void => {
    setTimeout(() => {
      resolve();
    }, ms);
  });
}
