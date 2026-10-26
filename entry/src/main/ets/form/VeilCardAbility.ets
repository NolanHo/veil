import { formBindingData, FormExtensionAbility, formProvider } from '@kit.FormKit';
import { Want } from '@kit.AbilityKit';
import { vpnExtension } from '@kit.NetworkKit';
import { preferences } from '@kit.ArkData';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { LocalRpc, RpcError } from '../core/LocalRpc';
import { formatBytes, formatRate } from '../core/Format';
import { EmptyParams, GroupStatus, ModeParams, Phase, SelectParams, Status } from '../model/Types';

const TAG = 'VeilCard';
const SOCK_TIMEOUT_MS: number = 1200;
const CALL_TIMEOUT_MS: number = 2500;
/** How long to wait for the VPN extension to publish its control socket. */
const HOST_WAIT_TRIES: number = 10;
const HOST_WAIT_STEP_MS: number = 300;
/** Don't re-ask the system to start the VPN extension more often than this. */
const START_DEBOUNCE_MS: number = 10000;

// Single-flight: repeated card taps must not spawn parallel start attempts, or
// the system keeps recreating the extension (and its core) under us.
let pendingCore: Promise<LocalRpc | null> | null = null;
let lastStartMs: number = 0;

/** Card render data; field names must match VeilCard's @LocalStorageProp keys. */
class CardData {
  phase: string = Phase.STOPPED;
  connected: boolean = false;
  node: string = '未选择节点';
  downRate: string = '—';
  upRate: string = '—';
  totalDown: string = '0 B';
  totalUp: string = '0 B';
  stateLabel: string = '未连接';
  accent: string = '#64748B';
  mode: string = 'rule';
  nodeCount: number = 0;
}

function sleep(ms: number): Promise<void> {
  return new Promise<void>((resolve: () => void): void => {
    setTimeout(resolve, ms);
  });
}

/**
 * 桌面卡片的进程侧。
 *
 * 卡片不常驻：系统按 updateDuration 唤醒本扩展（最短 30 分钟），用户点卡片
 * 按钮时也会唤醒一次。每次唤醒临时连一下 core 的 unix socket 取状态/执行
 * 动作，随后立即断开 —— 没有任何后台轮询，因此卡片本身的功耗为零。
 *
 * 「连接」按钮不必先打开 App：socket 不存在时先调
 * vpnExtension.startVpnExtensionAbility() 把 VPN 扩展（core 宿主）拉起来，
 * 等 socket 出现后再下发 start。首次系统会弹一次 VPN 授权，之后一点即连。
 */
export default class VeilCardAbility extends FormExtensionAbility {
  onAddForm(want: Want): formBindingData.FormBindingData {
    const formId: string = this.formIdOf(want);
    // Render the last snapshot synchronously: a card that only shows the node
    // after a tap looks broken. refresh() still runs and corrects it.
    const data: CardData = this.cachedData();
    if (formId.length > 0) {
      this.rememberForm(formId);
      this.refresh(formId);
    }
    return formBindingData.createFormBindingData(data);
  }

  /** Last pushed/observed snapshot, read synchronously from preferences. */
  private cachedData(): CardData {
    try {
      const store = preferences.getPreferencesSync(this.context, { name: 'veil_cards' });
      const raw: string = store.getSync('lastData', '') as string;
      if (raw.length === 0) {
        return new CardData();
      }
      const parsed = JSON.parse(raw) as CardData;
      const d: CardData = new CardData();
      d.phase = parsed.phase;
      d.connected = parsed.connected;
      d.node = parsed.node;
      d.downRate = parsed.downRate;
      d.upRate = parsed.upRate;
      d.totalDown = parsed.totalDown;
      d.totalUp = parsed.totalUp;
      d.stateLabel = parsed.stateLabel;
      d.accent = parsed.accent;
      d.mode = parsed.mode;
      d.nodeCount = parsed.nodeCount;
      return d;
    } catch (err) {
      return new CardData();
    }
  }

  /** Persists the snapshot so the next onAddForm can render it instantly. */
  private saveData(data: CardData): void {
    try {
      const store = preferences.getPreferencesSync(this.context, { name: 'veil_cards' });
      store.putSync('lastData', JSON.stringify(data));
      store.flush();
    } catch (err) {
      hilog.debug(0x00FF, TAG, 'saveData: %{public}s', String(err));
    }
  }

  /**
   * Records this card's id so the UI process can push updates after a mode or
   * node change; form ids are not exposed by formProvider.getFormsInfo.
   */
  private async rememberForm(formId: string): Promise<void> {
    try {
      const store = await preferences.getPreferences(this.context, 'veil_cards');
      const raw: string = await store.get('formIds', '[]') as string;
      const ids: string[] = JSON.parse(raw) as string[];
      if (ids.indexOf(formId) < 0) {
        ids.push(formId);
        await store.put('formIds', JSON.stringify(ids));
        await store.flush();
      }
    } catch (err) {
      hilog.debug(0x00FF, TAG, 'rememberForm: %{public}s', String(err));
    }
  }

  onUpdateForm(formId: string): void {
    this.refresh(formId);
  }

  onFormEvent(formId: string, message: string): void {
    hilog.info(0x00FF, TAG, 'onFormEvent %{public}s message=%{public}s', formId, message);
    this.handleEvent(formId, this.eventOf(message));
  }

  /**
   * The form framework delivers the whole params object as JSON (e.g.
   * {"event":"start"}); very old versions pass the raw string. Accept both.
   */
  private eventOf(message: string): string {
    try {
      const obj: Record<string, Object> = JSON.parse(message) as Record<string, Object>;
      const ev: Object | undefined = obj['event'];
      if (ev !== undefined) {
        return String(ev);
      }
      const msg: Object | undefined = obj['message'];
      if (msg !== undefined) {
        return String(msg);
      }
    } catch (err) {
      // not JSON: fall through to the raw string
    }
    return message;
  }

  onRemoveForm(formId: string): void {
    hilog.info(0x00FF, TAG, 'card removed %{public}s', formId);
    this.forgetForm(formId);
  }

  private async forgetForm(formId: string): Promise<void> {
    try {
      const store = await preferences.getPreferences(this.context, 'veil_cards');
      const raw: string = await store.get('formIds', '[]') as string;
      const ids: string[] = JSON.parse(raw) as string[];
      const idx: number = ids.indexOf(formId);
      if (idx >= 0) {
        ids.splice(idx, 1);
        await store.put('formIds', JSON.stringify(ids));
        await store.flush();
      }
    } catch (err) {
      hilog.debug(0x00FF, TAG, 'forgetForm: %{public}s', String(err));
    }
  }

  private formIdOf(want: Want): string {
    const params: Record<string, Object> | undefined = want.parameters;
    if (params === undefined) {
      return '';
    }
    const id: Object | undefined = params['ohos.extra.param.key.form_identity'];
    return id === undefined ? '' : String(id);
  }

  private socketPath(): string {
    return this.context.filesDir + '/veil.sock';
  }

  /** Sandbox path the VPN extension uses; tried when the form context points elsewhere. */
  private fallbackSocketPath(): string {
    return '/data/storage/el2/base/haps/entry/files/veil.sock';
  }

  /** Connects to the core socket, trying the form context path then the sandbox path. */
  private async connectAny(timeoutMs: number): Promise<LocalRpc | null> {
    const paths: string[] = [this.socketPath(), this.fallbackSocketPath()];
    for (let i = 0; i < paths.length; i++) {
      const rpc: LocalRpc = new LocalRpc();
      try {
        await rpc.connect(paths[i], timeoutMs);
        hilog.info(0x00FF, TAG, 'socket connected via %{public}s', paths[i]);
        return rpc;
      } catch (err) {
        rpc.close();
      }
    }
    return null;
  }

  private async withCore<T>(fn: (rpc: LocalRpc) => Promise<T>): Promise<T | null> {
    const rpc: LocalRpc = new LocalRpc();
    try {
      await rpc.connect(this.socketPath(), SOCK_TIMEOUT_MS);
      return await fn(rpc);
    } catch (err) {
      hilog.debug(0x00FF, TAG, 'core unreachable: %{public}s', String(err));
      return null;
    } finally {
      rpc.close();
    }
  }

  /**
   * Returns an open RPC connection, starting the VPN extension first when the
   * core is not running yet. Null when the host cannot be brought up.
   */
  private async ensureCore(): Promise<LocalRpc | null> {
    if (pendingCore !== null) {
      return pendingCore;
    }
    pendingCore = this.ensureCoreInner();
    try {
      return await pendingCore;
    } finally {
      pendingCore = null;
    }
  }

  private async ensureCoreInner(): Promise<LocalRpc | null> {
    const first: LocalRpc | null = await this.connectAny(600);
    if (first !== null) {
      return first;
    }

    const now: number = Date.now();
    if (now - lastStartMs > START_DEBOUNCE_MS) {
      lastStartMs = now;
      hilog.info(0x00FF, TAG, 'core down, starting VPN extension from card');
      try {
        const want: Want = { bundleName: 'com.nolanho.kitsune', abilityName: 'VeilVpnAbility' };
        await vpnExtension.startVpnExtensionAbility(want);
      } catch (err) {
        hilog.warn(0x00FF, TAG, 'startVpnExtensionAbility: %{public}s', String(err));
      }
    } else {
      hilog.info(0x00FF, TAG, 'start already attempted recently, waiting for the host');
    }

    for (let i = 0; i < HOST_WAIT_TRIES; i++) {
      await sleep(HOST_WAIT_STEP_MS);
      const rpc: LocalRpc | null = await this.connectAny(600);
      if (rpc !== null) {
        return rpc;
      }
    }
    return null;
  }

  private async refresh(formId: string): Promise<void> {
    const data: CardData = await this.collect();
    this.saveData(data);
    try {
      await formProvider.updateForm(formId, formBindingData.createFormBindingData(data));
    } catch (err) {
      hilog.warn(0x00FF, TAG, 'updateForm failed: %{public}s', String(err));
    }
  }

  private async collect(): Promise<CardData> {
    const data: CardData = new CardData();
    const empty: EmptyParams = {};
    const st: Status | null = await this.withCore<Status>(
      (rpc: LocalRpc) => rpc.request('status', empty, CALL_TIMEOUT_MS) as Promise<Status>);
    if (st === null) {
      return data;
    }
    const active: boolean = Phase.isActive(st.phase);
    data.phase = st.phase;
    data.connected = active;
    data.stateLabel = this.labelOf(st.phase);
    data.accent = this.accentOf(st.phase);
    data.downRate = formatRate(st.traffic.down_rate);
    data.upRate = formatRate(st.traffic.up_rate);
    data.totalDown = formatBytes(st.traffic.down);
    data.totalUp = formatBytes(st.traffic.up);
    data.mode = st.mode.length > 0 ? st.mode : 'rule';
    const groups = st.groups;
    for (let i = 0; i < groups.length; i++) {
      if (groups[i].now.length > 0) {
        data.node = groups[i].now;
      }
      data.nodeCount += groups[i].members.length;
    }
    return data;
  }

  /** Rotate to the next member of the group the active node belongs to. */
  private async rotateNode(): Promise<boolean> {
    const empty: EmptyParams = {};
    const rpc: LocalRpc | null = await this.ensureCore();
    if (rpc === null) {
      return false;
    }
    try {
      await this.rotateOn(rpc, empty);
      return true;
    } finally {
      rpc.close();
    }
  }

  private async rotateOn(rpc: LocalRpc, empty: EmptyParams): Promise<void> {
    {
      const groups = await rpc.request('groups', empty, CALL_TIMEOUT_MS) as GroupStatus[];
      for (let i = 0; i < groups.length; i++) {
        const g = groups[i];
        if (g.members.length === 0) {
          continue;
        }
        let idx: number = 0;
        for (let j = 0; j < g.members.length; j++) {
          if (g.members[j].tag === g.now) {
            idx = j;
            break;
          }
        }
        const next = g.members[(idx + 1) % g.members.length];
        const p: SelectParams = { group: g.tag, tag: next.tag };
        await rpc.request('select', p, CALL_TIMEOUT_MS * 2);
        hilog.info(0x00FF, TAG, 'rotated %{public}s -> %{public}s', g.tag, next.tag);
        return;
      }
    }
  }

  /** Switch the routing mode (rule / global / direct). */
  private async switchMode(mode: string): Promise<boolean> {
    const p: ModeParams = { mode: mode };
    const rpc: LocalRpc | null = await this.ensureCore();
    if (rpc === null) {
      return false;
    }
    try {
      await rpc.request('set_mode', p, CALL_TIMEOUT_MS * 2);
      hilog.info(0x00FF, TAG, 'mode -> %{public}s', mode);
      return true;
    } catch (err) {
      hilog.warn(0x00FF, TAG, 'set_mode failed: %{public}s', String(err));
      return false;
    } finally {
      rpc.close();
    }
  }

  private async handleEvent(formId: string, message: string): Promise<void> {
    const empty: EmptyParams = {};
    hilog.info(0x00FF, TAG, 'card action %{public}s', message);

    if (message === 'stop') {
      await this.withCore(async (rpc: LocalRpc) => {
        await rpc.request('stop', empty, CALL_TIMEOUT_MS * 4);
        return true;
      });
    } else if (message === 'nextNode') {
      if (!await this.rotateNode()) {
        await this.showOffline(formId, '核心未启动');
      }
    } else if (message.startsWith('mode:')) {
      if (!await this.switchMode(message.substring(5))) {
        await this.showOffline(formId, '核心未启动');
      }
    } else {
      const rpc: LocalRpc | null = await this.ensureCore();
      if (rpc !== null) {
        try {
          await rpc.request('start', empty, CALL_TIMEOUT_MS * 6);
        } catch (err) {
          hilog.warn(0x00FF, TAG, 'start failed: %{public}s', String(err));
        } finally {
          rpc.close();
        }
      } else {
        // Could not bring the host up from the card (e.g. VPN authorisation is
        // not granted yet). The card's 打开 button opens the app, where the
        // system prompt can be granted once; afterwards the card connects
        // directly.
        hilog.warn(0x00FF, TAG, 'host unavailable from card; grant VPN once in the app');
      }
    }

    // Phase changes asynchronously; refresh now and once the tunnel settles.
    await this.refresh(formId);
    setTimeout(() => {
      this.refresh(formId);
    }, 3000);
    setTimeout(() => {
      this.refresh(formId);
    }, 8000);
  }

  /** Renders an explicit failure on the card (never a silent no-op). */
  private async showOffline(formId: string, label: string): Promise<void> {
    const data: CardData = this.cachedData();
    data.stateLabel = label;
    data.accent = '#F87171';
    try {
      await formProvider.updateForm(formId, formBindingData.createFormBindingData(data));
    } catch (err) {
      hilog.warn(0x00FF, TAG, 'showOffline: %{public}s', String(err));
    }
  }

  private labelOf(phase: string): string {
    if (phase === Phase.RUNNING) {
      return '已连接';
    }
    if (phase === Phase.DEGRADED) {
      return '已降级';
    }
    if (phase === Phase.STARTING) {
      return '连接中';
    }
    if (phase === Phase.STOPPING) {
      return '断开中';
    }
    if (phase === Phase.FAILED) {
      return '失败';
    }
    return '未连接';
  }

  private accentOf(phase: string): string {
    if (phase === Phase.RUNNING) {
      return '#5EEAD4';
    }
    if (phase === Phase.DEGRADED) {
      return '#FBBF24';
    }
    if (phase === Phase.STARTING || phase === Phase.STOPPING) {
      return '#818CF8';
    }
    if (phase === Phase.FAILED) {
      return '#F87171';
    }
    return '#64748B';
  }
}
