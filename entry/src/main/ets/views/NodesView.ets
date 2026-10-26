import { CoreClient } from '../core/CoreClient';
import { K_STATUS, Store } from '../core/Store';
import { Phase, Status, emptyStatus } from '../model/Types';
import { formatDelay } from '../core/Format';
import { GroupStatus, Node, NodeStatus, VeilConfig } from '../model/Types';
import { delayColor } from '../theme/Theme';
import { EmptyBlock, Hairline, Tag } from './Ui';
import { errorText, toast } from './Common';

interface DelayEntry {
  tag: string;
  delay: number;
  err: string;
}

const REFRESH_MS: number = 8000;

/**
 * 节点 — policy groups straight from `status.groups`.
 *
 * Nothing is cached: if the core says a node has no measured delay, the UI says
 * 未知, not "0 ms". Selecting a member is optimistic-free too: we send `select`
 * and re-read the group the core returns.
 */
@Component
export struct NodesView {
  @StorageProp('veilDark') dark: boolean = true;
  @Link @Watch('onCoreReady') coreReady: boolean;
  @StorageProp(K_STATUS) status: Status = emptyStatus();
  @State delays: DelayEntry[] = [];
  @State refreshing: boolean = false;
  @State probing: string = '';
  @State collapsed: string[] = [];
  // Inline node editor (no modal controller needed): long-press a node to edit
  // its display name and connection parameters.
  @State editing: boolean = false;
  @State eTag: string = '';
  @State eType: string = '';
  @State eRemark: string = '';
  @State eServer: string = '';
  @State ePort: string = '';
  @State eUUID: string = '';
  @State eFlow: string = '';
  @State eSaving: boolean = false;

  private groupsOf(): GroupStatus[] {
    const g: GroupStatus[] = this.status.groups;
    if (g === undefined || g === null) {
      return [];
    }
    for (let i = 0; i < g.length; i++) {
      if (g[i].members === undefined || g[i].members === null) {
        g[i].members = [];
      }
    }
    return g;
  }

  private timer: number = -1;
  private loading: boolean = false;

  aboutToAppear(): void {
    if (this.coreReady) {
      this.startPolling();
    }
  }

  aboutToDisappear(): void {
    this.stopPolling();
  }

  onCoreReady(): void {
    if (this.coreReady) {
      this.startPolling();
    } else {
      this.stopPolling();
    }
  }

  private startPolling(): void {
    this.stopPolling();
    this.load();
    this.timer = setInterval(() => {
      this.load();
    }, REFRESH_MS);
  }

  private stopPolling(): void {
    if (this.timer >= 0) {
      clearInterval(this.timer);
      this.timer = -1;
    }
  }

  private async load(): Promise<void> {
    if (this.loading || !this.coreReady) {
      return;
    }
    this.loading = true;
    try {
      await Store.get().refresh();
    } catch (err) {
      // Keep the last known list; the banner reports connectivity.
    }
    this.loading = false;
  }

  private delayOf(node: NodeStatus): number {
    for (let i = 0; i < this.delays.length; i++) {
      if (this.delays[i].tag === node.tag) {
        return this.delays[i].delay;
      }
    }
    return node.delay_ms;
  }

  private errorOf(node: NodeStatus): string {
    for (let i = 0; i < this.delays.length; i++) {
      if (this.delays[i].tag === node.tag) {
        return this.delays[i].err;
      }
    }
    return '';
  }

  private setDelay(tag: string, delay: number, err: string): void {
    const next: DelayEntry[] = this.delays.slice();
    let found: boolean = false;
    for (let i = 0; i < next.length; i++) {
      if (next[i].tag === tag) {
        const entry: DelayEntry = { tag: tag, delay: delay, err: err };
        next[i] = entry;
        found = true;
        break;
      }
    }
    if (!found) {
      const entry: DelayEntry = { tag: tag, delay: delay, err: err };
      next.push(entry);
    }
    this.delays = next;
  }

  private async probe(tag: string): Promise<void> {
    if (this.probing.length > 0 || !this.coreReady) {
      return;
    }
    this.probing = tag;
    try {
      const r = await CoreClient.get().delay(tag, 4000);
      const err: string = r.err === undefined ? '' : r.err;
      this.setDelay(r.tag, r.delay_ms, err);
      if (err.length > 0) {
        toast(tag + ': ' + err);
      }
    } catch (err) {
      this.setDelay(tag, 0, errorText(err));
      toast(errorText(err));
    }
    this.probing = '';
  }

  private async probeAll(): Promise<void> {
    const tags: string[] = [];
    for (let i = 0; i < this.groupsOf().length; i++) {
      const members: NodeStatus[] = this.groupsOf()[i].members;
      for (let j = 0; j < members.length; j++) {
        tags.push(members[j].tag);
      }
    }
    for (let i = 0; i < tags.length; i++) {
      this.probing = tags[i];
      try {
        const r = await CoreClient.get().delay(tags[i], 4000);
        this.setDelay(r.tag, r.delay_ms, r.err === undefined ? '' : r.err);
      } catch (err) {
        this.setDelay(tags[i], 0, errorText(err));
      }
    }
    this.probing = '';
    await this.load();
  }

  private onPull(): void {
    this.refreshing = true;
    this.probeAll().then(() => {
      this.refreshing = false;
    });
  }

  private async openEditor(tag: string): Promise<void> {
    try {
      const cfg: VeilConfig = await CoreClient.get().config();
      for (let i = 0; i < cfg.nodes.length; i++) {
        const n: Node = cfg.nodes[i];
        if (n.tag !== tag) {
          continue;
        }
        this.eTag = n.tag;
        this.eType = n.type;
        this.eRemark = n.remark === undefined ? '' : n.remark;
        this.eServer = n.server;
        this.ePort = n.port.toString();
        this.eUUID = n.uuid === undefined ? '' : n.uuid;
        this.eFlow = n.flow === undefined ? '' : n.flow;
        this.editing = true;
        return;
      }
      toast('找不到节点 ' + tag);
    } catch (err) {
      toast(errorText(err));
    }
  }

  private async saveEditor(): Promise<void> {
    if (this.eSaving) {
      return;
    }
    this.eSaving = true;
    try {
      const cfg: VeilConfig = await CoreClient.get().config();
      for (let i = 0; i < cfg.nodes.length; i++) {
        const n: Node = cfg.nodes[i];
        if (n.tag !== this.eTag) {
          continue;
        }
        n.remark = this.eRemark;
        if (this.eServer.length > 0) {
          n.server = this.eServer;
        }
        const port: number = Number(this.ePort);
        if (!isNaN(port) && port > 0 && port < 65536) {
          n.port = port;
        }
        if (n.uuid !== undefined) {
          n.uuid = this.eUUID;
        }
        if (n.flow !== undefined) {
          n.flow = this.eFlow;
        }
      }
      await CoreClient.get().setConfig(cfg);
      this.editing = false;
      await this.load();
      toast('已保存（重连后完全生效）');
    } catch (err) {
      toast(errorText(err));
    }
    this.eSaving = false;
  }

  private async choose(group: string, tag: string): Promise<void> {
    if (!this.coreReady) {
      toast('核心不可用');
      return;
    }
    try {
      await Store.get().select(group, tag);
      await this.load();
      // Tell the truth: with the tunnel down this is a saved choice, not a
      // live switch.
      const st: Status = AppStorage.get<Status>(K_STATUS) as Status;
      const live: boolean = st !== undefined && st !== null && Phase.isActive(st.phase);
      toast(live ? '已切换到 ' + tag : '已选择 ' + tag + '，连接后生效');
    } catch (err) {
      toast(errorText(err));
    }
  }

  private isCollapsed(tag: string): boolean {
    return this.collapsed.indexOf(tag) >= 0;
  }

  private toggleGroup(tag: string): void {
    const next: string[] = this.collapsed.slice();
    const idx: number = next.indexOf(tag);
    if (idx >= 0) {
      next.splice(idx, 1);
    } else {
      next.push(tag);
    }
    this.collapsed = next;
  }

  private delayLabel(node: NodeStatus): string {
    const d: number = this.delayOf(node);
    if (this.errorOf(node).length > 0) {
      return '超时';
    }
    if (d <= 0) {
      return this.probing === node.tag ? '测速中' : '未知';
    }
    return formatDelay(d);
  }

  @Builder
  probeSwipe(tag: string) {
    Column() {
      Text(this.probing === tag ? '测速中' : '测速')
        .fontSize(12)
        .fontColor($r('app.color.veil_bg'))
        .padding({ left: 14, right: 14, top: 6, bottom: 6 })
        .borderRadius(8)
        .backgroundColor($r('app.color.veil_teal'))
    }
    .width(84)
    .height('100%')
    .justifyContent(FlexAlign.Center)
    .backgroundColor($r('app.color.veil_surface'))
    .onClick(() => {
      this.probe(tag);
    })
  }

  /**
   * The group head shows the *current member*: the node's display name when the
   * selection is a node tag, the built-in name (`direct` / `reject`) when the
   * core selected a built-in, and 自动 when the core has not chosen yet. Never
   * an empty string and never `undefined`.
   */
  private nowLabel(group: GroupStatus): string {
    const now: string = group.now;
    if (now === undefined || now === null || now.length === 0) {
      return '自动';
    }
    const members: NodeStatus[] = group.members === undefined || group.members === null ? [] : group.members;
    for (let i = 0; i < members.length; i++) {
      const member: NodeStatus = members[i];
      if (member.tag === now) {
        const remark: string = member.remark === undefined ? '' : member.remark;
        return remark.length > 0 ? remark : now;
      }
    }
    return now;
  }

  @Builder
  groupHeader(group: GroupStatus) {
    Row({ space: 8 }) {
      Text(group.tag)
        .fontSize(13)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.veil_text'))
        .layoutWeight(1)
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })

      Tag({ label: group.type, tone: this.dark ? '#6366F1' : '#5B5BE6' })

      Text(this.nowLabel(group))
        .fontSize(11)
        .fontColor($r('app.color.veil_text_dim'))
        .maxLines(1)
        .textOverflow({ overflow: TextOverflow.Ellipsis })
        .constraintSize({ maxWidth: 110 })

      Text(this.isCollapsed(group.tag) ? '展开' : '收起')
        .fontSize(11)
        .fontColor($r('app.color.veil_text_faint'))
    }
    .width('100%')
    .padding({ top: 10, bottom: 10 })
    .onClick(() => {
      this.toggleGroup(group.tag);
    })
  }

  @Builder
  memberRow(group: string, node: NodeStatus, selected: boolean) {
    Row({ space: 10 }) {
      Column()
        .width(2)
        .height(22)
        .borderRadius(1)
        .backgroundColor(selected ? $r('app.color.veil_teal') : Color.Transparent)

      Column({ space: 2 }) {
        Text(node.remark !== undefined && node.remark.length > 0 ? node.remark : node.tag)
          .fontSize(14)
          .fontColor(selected ? $r('app.color.veil_teal') : $r('app.color.veil_text'))
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .width('100%')
          .textAlign(TextAlign.Start)

        Text(node.type + ' · ' + node.tag)
          .fontSize(10)
          .fontColor($r('app.color.veil_text_faint'))
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .width('100%')
          .textAlign(TextAlign.Start)
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      Text(this.delayLabel(node))
        .fontSize(12)
        .fontFeature('"tnum" 1')
        .fontColor(this.errorOf(node).length > 0 ?
          (this.dark ? '#F87171' : '#DC2626') : delayColor(this.dark, this.delayOf(node)))
        .constraintSize({ minWidth: 52 })
        .textAlign(TextAlign.End)
    }
    .width('100%')
    .padding({ top: 10, bottom: 10, right: 4 })
    .borderRadius(10)
    .backgroundColor(selected ? $r('app.color.veil_surface_alt') : Color.Transparent)
    .onClick(() => {
      this.choose(group, node.tag);
    })
    .gesture(LongPressGesture().onAction(() => {
      this.openEditor(node.tag);
    }))
  }

  @Builder
  editorBlock() {
    Column({ space: 8 }) {
      Row() {
        Text('编辑 ' + this.eTag)
          .fontSize(13)
          .fontWeight(FontWeight.Medium)
          .fontColor($r('app.color.veil_text'))
        Blank()
        Text(this.eSaving ? '保存中' : '保存')
          .fontSize(12)
          .fontColor($r('app.color.veil_teal'))
          .padding({ left: 10, right: 10, top: 4, bottom: 4 })
          .borderRadius(8)
          .border({ width: 0.5, color: $r('app.color.veil_hairline') })
          .onClick(() => {
            this.saveEditor();
          })
        Text('取消')
          .fontSize(12)
          .fontColor($r('app.color.veil_text_dim'))
          .padding({ left: 10, right: 10, top: 4, bottom: 4 })
          .onClick(() => {
            this.editing = false;
          })
      }
      .width('100%')

      TextInput({ text: this.eRemark, placeholder: '显示名称（备注）' })
        .height(36)
        .fontSize(13)
        .onChange((v: string) => {
          this.eRemark = v;
        })

      Row({ space: 8 }) {
        TextInput({ text: this.eServer, placeholder: '服务器' })
          .height(36)
          .fontSize(13)
          .layoutWeight(2)
          .onChange((v: string) => {
            this.eServer = v;
          })
        TextInput({ text: this.ePort, placeholder: '端口' })
          .height(36)
          .fontSize(13)
          .type(InputType.Number)
          .layoutWeight(1)
          .onChange((v: string) => {
            this.ePort = v;
          })
      }
      .width('100%')

      if (this.eUUID.length > 0 || this.eType === 'vless' || this.eType === 'vmess') {
        TextInput({ text: this.eUUID, placeholder: 'UUID / 密码' })
          .height(36)
          .fontSize(13)
          .onChange((v: string) => {
            this.eUUID = v;
          })
      }

      if (this.eType === 'vless') {
        TextInput({ text: this.eFlow, placeholder: 'flow（如 xtls-rprx-vision）' })
          .height(36)
          .fontSize(13)
          .onChange((v: string) => {
            this.eFlow = v;
          })
      }

      Text('类型 ' + this.eType + ' · tag ' + this.eTag + '（tag 为订阅标识，不改名）')
        .fontSize(10)
        .fontColor($r('app.color.veil_text_faint'))
    }
    .width('100%')
    .padding(12)
    .borderRadius(14)
    .backgroundColor($r('app.color.veil_surface_alt'))
    .border({ width: 0.5, color: $r('app.color.veil_hairline') })
    .margin({ bottom: 8 })
  }

  private async retryCore(): Promise<void> {
    const ok: boolean = await CoreClient.get().reconnect();
    this.coreReady = ok;
    if (ok) {
      await this.load();
    } else {
      toast('核心仍不可用：' + CoreClient.get().getLastError());
    }
  }

  build() {
    Column() {
      if (!this.coreReady) {
        EmptyBlock({
          title: '核心未启动',
          subtitle: '后台核心进程不在运行，节点列表暂时读不到。点下面重试即可，不需要先连接。',
          action: '重试启动核心',
          onAction: () => {
            this.retryCore();
          }
        })
      } else if (this.groupsOf().length === 0) {
        EmptyBlock({
          title: '还没有策略组',
          subtitle: '在「规则」页导入订阅或节点后，这里会出现可切换的出口组。'
        })
      } else {
        if (this.editing) {
          this.editorBlock()
        }
        Refresh({ refreshing: $$this.refreshing }) {
          List({ space: 0 }) {
            ForEach(this.groupsOf(), (group: GroupStatus) => {
              ListItem() {
                this.groupHeader(group)
              }

              if (!this.isCollapsed(group.tag)) {
                ForEach(group.members, (node: NodeStatus) => {
                  ListItem() {
                    this.memberRow(group.tag, node, group.now === node.tag)
                  }
                  .swipeAction({ end: this.probeSwipe(node.tag) })
                }, (node: NodeStatus) => group.tag + '/' + node.tag)
              }

              ListItem() {
                Hairline()
              }
            }, (group: GroupStatus) => group.tag)
          }
          .width('100%')
          .height('100%')
          .scrollBar(BarState.Off)
          .edgeEffect(EdgeEffect.Spring)
        }
        .onRefreshing(() => {
          this.onPull();
        })
        .width('100%')
        .height('100%')
      }
    }
    .width('100%')
    .height('100%')
    .padding({ left: 18, right: 18 })
    .onVisibleAreaChange([0.0, 1.0], (isVisible: boolean, ratio: number) => {
      if (isVisible && ratio > 0) {
        if (this.coreReady) {
          this.startPolling();
        }
      } else {
        this.stopPolling();
      }
    })
  }
}
