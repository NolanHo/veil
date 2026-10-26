import { CoreClient } from '../core/CoreClient';
import { formatBytes, formatClock, formatCount } from '../core/Format';
import { Conn, emptyConfig, LogLine, LogsResult, Status, VeilConfig, VersionResult } from '../model/Types';
import { EmptyBlock, Hairline, KeyValueRow, SectionTitle } from './Ui';
import { Chip } from './Ui';
import { errorText, toast } from './Common';

const LOG_POLL_MS: number = 1500;
const CONN_POLL_MS: number = 3000;
const LOG_CAP: number = 300;

/**
 * 设置 — tun parameters, log level, traffic totals, live connections, the log
 * ring buffer and the about block.
 *
 * Every switch here writes the *whole* config back through `set_config`
 * (the core replaces, it does not merge), so `this.cfg` is always the last
 * complete document we read from the core.
 */
@Component
export struct SettingsView {
  @StorageProp('veilDark') dark: boolean = true;
  @Link @Watch('onCoreReady') coreReady: boolean;

  @State cfg: VeilConfig = emptyConfig();
  @State loaded: boolean = false;
  @State mtuText: string = '1400';
  @State ipv4Text: string = '';
  @State dnsText: string = '';
  @State mixedText: string = '';

  @State trafficUp: number = 0;
  @State trafficDown: number = 0;
  @State trafficTotal: number = 0;

  @State conns: Conn[] = [];
  @State showConns: boolean = false;

  @State logLines: LogLine[] = [];
  @State logLevel: string = '';
  @State autoScroll: boolean = true;

  @State version: string = '';
  @State commit: string = '';
  @State saving: boolean = false;

  private logTimer: number = -1;
  private connTimer: number = -1;
  private afterId: number = 0;
  private logScroller: Scroller = new Scroller();
  private logBusy: boolean = false;

  aboutToAppear(): void {
    if (this.coreReady) {
      this.start();
    }
  }

  aboutToDisappear(): void {
    this.stop();
  }

  onCoreReady(): void {
    if (this.coreReady) {
      this.start();
    } else {
      this.stop();
    }
  }

  private start(): void {
    this.stop();
    this.loadConfig();
    this.loadVersion();
    this.refreshTraffic();
    this.pullLogs();
    this.logTimer = setInterval(() => {
      this.pullLogs();
    }, LOG_POLL_MS);
  }

  private stop(): void {
    if (this.logTimer >= 0) {
      clearInterval(this.logTimer);
      this.logTimer = -1;
    }
    if (this.connTimer >= 0) {
      clearInterval(this.connTimer);
      this.connTimer = -1;
    }
  }

  private async loadConfig(): Promise<void> {
    if (!this.coreReady) {
      return;
    }
    try {
      const cfg: VeilConfig = await CoreClient.get().config();
      this.cfg = cfg;
      this.mtuText = cfg.tun.mtu.toString();
      this.ipv4Text = cfg.tun.ipv4;
      this.dnsText = cfg.tun.dns;
      this.mixedText = cfg.mixed;
      this.loaded = true;
      if (this.version.length === 0) {
        await this.loadVersion();
      }
    } catch (err) {
      toast(errorText(err));
    }
  }

  private async loadVersion(): Promise<void> {
    try {
      const v: VersionResult = await CoreClient.get().version();
      this.version = v.version;
      this.commit = v.commit === undefined ? '' : v.commit;
    } catch (err) {
      // Version is cosmetic; keep silent so a dead core doesn't spam toasts.
    }
  }

  private async refreshTraffic(): Promise<void> {
    try {
      const s: Status = await CoreClient.get().status();
      this.trafficUp = s.traffic.up;
      this.trafficDown = s.traffic.down;
      this.trafficTotal = s.traffic.total_conn;
    } catch (err) {
      // banner handles it
    }
  }

  /** Copies the config and applies one mutation, then writes it back. */
  private async apply(mutator: (c: VeilConfig) => void): Promise<void> {
    if (this.saving) {
      return;
    }
    if (!this.coreReady) {
      toast('核心不可用');
      return;
    }
    this.saving = true;
    const copy: VeilConfig = cloneConfig(this.cfg);
    mutator(copy);
    try {
      await CoreClient.get().setConfig(copy);
      this.cfg = copy;
      this.mtuText = copy.tun.mtu.toString();
      this.ipv4Text = copy.tun.ipv4;
      this.dnsText = copy.tun.dns;
      this.mixedText = copy.mixed;
      toast('配置已保存');
      await this.refreshTraffic();
    } catch (err) {
      toast(errorText(err));
    }
    this.saving = false;
  }

  private commitMtu(): void {
    const v: number = parseInt(this.mtuText, 10);
    if (isNaN(v) || v < 576 || v > 9000) {
      toast('MTU 需在 576 - 9000 之间');
      this.mtuText = this.cfg.tun.mtu.toString();
      return;
    }
    if (v === this.cfg.tun.mtu) {
      return;
    }
    this.apply((c: VeilConfig) => {
      c.tun.mtu = v;
    });
  }

  private commitIpv4(): void {
    const v: string = this.ipv4Text.trim();
    if (v.length === 0 || v === this.cfg.tun.ipv4) {
      return;
    }
    this.apply((c: VeilConfig) => {
      c.tun.ipv4 = v;
    });
  }

  private commitDns(): void {
    const v: string = this.dnsText.trim();
    if (v.length === 0 || v === this.cfg.tun.dns) {
      return;
    }
    this.apply((c: VeilConfig) => {
      c.tun.dns = v;
    });
  }

  /** "host:port" — the only shape config.Validate accepts for a listen address. */
  private commitMixed(): void {
    const v: string = this.mixedText.trim();
    if (v === this.cfg.mixed) {
      return;
    }
    const parts: string[] = v.split(':');
    const port: number = parts.length === 2 ? parseInt(parts[1], 10) : NaN;
    if (parts.length !== 2 || parts[0].length === 0 || isNaN(port) || port <= 0 || port > 65535) {
      toast('格式应为 host:port，例如 127.0.0.1:7890');
      this.mixedText = this.cfg.mixed;
      return;
    }
    this.apply((c: VeilConfig) => {
      c.mixed = v;
    });
  }

  private setLogLevel(level: string): void {
    if (level === this.cfg.log_level) {
      return;
    }
    this.apply((c: VeilConfig) => {
      c.log_level = level;
    });
  }

  private setTunFlag(autoRoute: boolean): void {
    this.apply((c: VeilConfig) => {
      c.tun.auto_route = autoRoute;
    });
  }

  private setBypassLan(on: boolean): void {
    this.apply((c: VeilConfig) => {
      c.tun.bypass_lan = on;
    });
  }

  private async resetStats(): Promise<void> {
    try {
      await CoreClient.get().resetStats();
      this.trafficUp = 0;
      this.trafficDown = 0;
      this.trafficTotal = 0;
      toast('流量统计已重置');
    } catch (err) {
      toast(errorText(err));
    }
  }

  private async toggleConns(): Promise<void> {
    this.showConns = !this.showConns;
    if (this.showConns) {
      await this.pullConns();
      if (this.connTimer < 0) {
        this.connTimer = setInterval(() => {
          this.pullConns();
        }, CONN_POLL_MS);
      }
    } else {
      if (this.connTimer >= 0) {
        clearInterval(this.connTimer);
        this.connTimer = -1;
      }
    }
  }

  private async pullConns(): Promise<void> {
    if (!this.coreReady) {
      return;
    }
    try {
      this.conns = await CoreClient.get().conns();
    } catch (err) {
      // keep last snapshot
    }
  }

  private async closeConn(c: Conn): Promise<void> {
    try {
      await CoreClient.get().closeConn(c.id);
      await this.pullConns();
      toast('已断开 ' + c.dest);
    } catch (err) {
      toast(errorText(err));
    }
  }

  private closeAll(): void {
    AlertDialog.show({
      title: '断开全部连接',
      message: '所有活动连接将被关闭，之后的流量会重新建立连接。',
      primaryButton: {
        value: '取消',
        action: () => {
        }
      },
      secondaryButton: {
        value: '断开',
        fontColor: '#DC2626',
        action: () => {
          CoreClient.get().closeAll().then(() => {
            this.pullConns();
            toast('已断开全部连接');
          }).catch((e: Object) => {
            toast(errorText(e));
          });
        }
      }
    });
  }

  private applyLogLevelFilter(level: string): void {
    this.logLevel = level;
    this.logLines = [];
    this.afterId = 0;
    this.pullLogs();
  }

  private async pullLogs(): Promise<void> {
    if (this.logBusy || !this.coreReady) {
      return;
    }
    this.logBusy = true;
    try {
      const r: LogsResult = await CoreClient.get().logs(this.afterId, 200, this.logLevel);
      if (r.lines !== undefined && r.lines.length > 0) {
        const next: LogLine[] = this.logLines.slice();
        for (let i = 0; i < r.lines.length; i++) {
          next.push(r.lines[i]);
        }
        while (next.length > LOG_CAP) {
          next.shift();
        }
        this.logLines = next;
        this.afterId = r.last_id;
        if (this.autoScroll) {
          this.logScroller.scrollEdge(Edge.Bottom);
        }
      }
    } catch (err) {
      // silent: the logs panel is a debugging aid, not a health signal
    }
    this.logBusy = false;
  }

  private levelTone(level: string): string {
    const l: string = level.toLowerCase();
    if (l === 'error' || l === 'fatal') {
      return this.dark ? '#F87171' : '#DC2626';
    }
    if (l === 'warn' || l === 'warning') {
      return this.dark ? '#FBBF24' : '#D97706';
    }
    if (l === 'debug') {
      return this.dark ? '#59616F' : '#96A0B0';
    }
    return this.dark ? '#8B94A5' : '#5B6474';
  }

  @Builder
  connRow(c: Conn) {
    Row({ space: 10 }) {
      Column({ space: 2 }) {
        Text(c.dest)
          .fontSize(12)
          .fontColor($r('app.color.veil_text'))
          .width('100%')
          .textAlign(TextAlign.Start)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        Text(c.network + ' · ' + c.outbound + (c.rule !== undefined && c.rule.length > 0 ?
          ' · ' + c.rule : ''))
          .fontSize(10)
          .fontColor($r('app.color.veil_text_faint'))
          .width('100%')
          .textAlign(TextAlign.Start)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)

      Text(formatBytes(c.up + c.down))
        .fontSize(11)
        .fontFeature('"tnum" 1')
        .fontColor($r('app.color.veil_text_dim'))

      Text('断开')
        .fontSize(11)
        .fontColor($r('app.color.veil_err'))
        .padding({ left: 8, right: 4, top: 4, bottom: 4 })
    }
    .width('100%')
    .padding({ top: 8, bottom: 8 })
    .alignItems(VerticalAlign.Center)
    .onClick(() => {
      // Whole row is the hit target; tapping a live connection kills it.
      this.closeConn(c);
    })
  }

  build() {
    Column() {
      if (!this.coreReady) {
        EmptyBlock({
          title: '核心不可用',
          subtitle: '设置项直接写入核心配置，未连接时无法读取或修改。'
        })
      } else {
        Scroll() {
          Column({ space: 14 }) {
            // ---- tun ----------------------------------------------------
            Column({ space: 0 }) {
              SectionTitle({ title: '隧道' })

              Row() {
                Text('MTU')
                  .fontSize(13)
                  .fontColor($r('app.color.veil_text_dim'))
                Blank()
                TextInput({ text: $$this.mtuText })
                  .width(96)
                  .height(34)
                  .fontSize(13)
                  .type(InputType.Number)
                  .textAlign(TextAlign.End)
                  .backgroundColor($r('app.color.veil_surface_alt'))
                  .borderRadius(10)
                  .onSubmit(() => {
                    this.commitMtu();
                  })
              }
              .width('100%')
              .padding({ top: 6, bottom: 6 })

              Hairline()

              Row() {
                Text('隧道地址')
                  .fontSize(13)
                  .fontColor($r('app.color.veil_text_dim'))
                Blank()
                TextInput({ text: $$this.ipv4Text })
                  .width(160)
                  .height(34)
                  .fontSize(13)
                  .textAlign(TextAlign.End)
                  .backgroundColor($r('app.color.veil_surface_alt'))
                  .borderRadius(10)
                  .onSubmit(() => {
                    this.commitIpv4();
                  })
              }
              .width('100%')
              .padding({ top: 6, bottom: 6 })

              Hairline()

              Row() {
                Text('DNS')
                  .fontSize(13)
                  .fontColor($r('app.color.veil_text_dim'))
                Blank()
                TextInput({ text: $$this.dnsText })
                  .width(160)
                  .height(34)
                  .fontSize(13)
                  .textAlign(TextAlign.End)
                  .backgroundColor($r('app.color.veil_surface_alt'))
                  .borderRadius(10)
                  .onSubmit(() => {
                    this.commitDns();
                  })
              }
              .width('100%')
              .padding({ top: 6, bottom: 6 })

              Hairline()

              Row() {
                Text('自动路由')
                  .fontSize(13)
                  .fontColor($r('app.color.veil_text_dim'))
                Blank()
                Toggle({ type: ToggleType.Switch, isOn: this.cfg.tun.auto_route })
                  .selectedColor($r('app.color.veil_teal'))
                  .onChange((on: boolean) => {
                    this.setTunFlag(on);
                  })
              }
              .width('100%')
              .padding({ top: 6, bottom: 6 })

              Hairline()

              Row() {
                Text('绕过局域网')
                  .fontSize(13)
                  .fontColor($r('app.color.veil_text_dim'))
                Blank()
                Toggle({ type: ToggleType.Switch, isOn: this.cfg.tun.bypass_lan })
                  .selectedColor($r('app.color.veil_teal'))
                  .onChange((on: boolean) => {
                    this.setBypassLan(on);
                  })
              }
              .width('100%')
              .padding({ top: 6, bottom: 6 })

              Hairline()

              Row() {
                Text('本地混合端口')
                  .fontSize(13)
                  .fontColor($r('app.color.veil_text_dim'))
                Blank()
                TextInput({ text: $$this.mixedText })
                  .width(160)
                  .height(34)
                  .fontSize(13)
                  .textAlign(TextAlign.End)
                  .backgroundColor($r('app.color.veil_surface_alt'))
                  .borderRadius(10)
                  .onSubmit(() => {
                    this.commitMixed();
                  })
              }
              .width('100%')
              .padding({ top: 6, bottom: 6 })
            }
            .width('100%')
            .padding(16)
            .borderRadius(20)
            .backgroundColor($r('app.color.veil_surface'))
            .border({ width: 0.5, color: $r('app.color.veil_hairline') })

            // ---- log level ---------------------------------------------
            Column({ space: 10 }) {
              Text('日志级别')
                .fontSize(13)
                .fontColor($r('app.color.veil_text_dim'))
                .width('100%')
                .textAlign(TextAlign.Start)

              Row({ space: 8 }) {
                Chip({
                  label: 'debug', active: this.cfg.log_level === 'debug',
                  tone: this.dark ? '#5EEAD4' : '#0E9F8E',
                  onTap: () => {
                    this.setLogLevel('debug');
                  }
                })
                Chip({
                  label: 'info', active: this.cfg.log_level === 'info',
                  tone: this.dark ? '#5EEAD4' : '#0E9F8E',
                  onTap: () => {
                    this.setLogLevel('info');
                  }
                })
                Chip({
                  label: 'warn', active: this.cfg.log_level === 'warn',
                  tone: this.dark ? '#FBBF24' : '#D97706',
                  onTap: () => {
                    this.setLogLevel('warn');
                  }
                })
                Chip({
                  label: 'error', active: this.cfg.log_level === 'error',
                  tone: this.dark ? '#F87171' : '#DC2626',
                  onTap: () => {
                    this.setLogLevel('error');
                  }
                })
              }
              .width('100%')
            }
            .width('100%')
            .padding(16)
            .borderRadius(20)
            .backgroundColor($r('app.color.veil_surface'))
            .border({ width: 0.5, color: $r('app.color.veil_hairline') })

            // ---- traffic -------------------------------------------------
            Column({ space: 0 }) {
              Row() {
                SectionTitle({ title: '流量' })
                Blank()
                Text('重置')
                  .fontSize(12)
                  .fontColor($r('app.color.veil_err'))
                  .onClick(() => {
                    this.resetStats();
                  })
              }
              .width('100%')

              KeyValueRow({ label: '累计上传', value: formatBytes(this.trafficUp) })
              Hairline()
              KeyValueRow({ label: '累计下载', value: formatBytes(this.trafficDown) })
              Hairline()
              KeyValueRow({ label: '累计连接', value: formatCount(this.trafficTotal) })
            }
            .width('100%')
            .padding(16)
            .borderRadius(20)
            .backgroundColor($r('app.color.veil_surface'))
            .border({ width: 0.5, color: $r('app.color.veil_hairline') })

            // ---- connections ---------------------------------------------
            Column({ space: 6 }) {
              Row() {
                Text('活动连接')
                  .fontSize(13)
                  .fontWeight(FontWeight.Medium)
                  .fontColor($r('app.color.veil_text_dim'))
                Blank()
                Text(this.showConns ? '收起' : '查看')
                  .fontSize(12)
                  .fontColor($r('app.color.veil_teal'))
                  .onClick(() => {
                    this.toggleConns();
                  })
              }
              .width('100%')

              if (this.showConns) {
                if (this.conns.length === 0) {
                  Text('当前没有活动连接。')
                    .fontSize(12)
                    .fontColor($r('app.color.veil_text_faint'))
                    .width('100%')
                    .textAlign(TextAlign.Start)
                    .padding({ top: 6, bottom: 6 })
                } else {
                  ForEach(this.conns, (c: Conn) => {
                    this.connRow(c)
                    Hairline()
                  }, (c: Conn) => c.id.toString())

                  Text('断开全部')
                    .fontSize(12)
                    .fontColor($r('app.color.veil_err'))
                    .padding({ top: 10 })
                    .onClick(() => {
                      this.closeAll();
                    })
                }
              }
            }
            .width('100%')
            .padding(16)
            .borderRadius(20)
            .backgroundColor($r('app.color.veil_surface'))
            .border({ width: 0.5, color: $r('app.color.veil_hairline') })

            // ---- logs -----------------------------------------------------
            Column({ space: 8 }) {
              Row() {
                Text('日志')
                  .fontSize(13)
                  .fontWeight(FontWeight.Medium)
                  .fontColor($r('app.color.veil_text_dim'))
                Blank()
                Text(this.autoScroll ? '自动滚动' : '已暂停滚动')
                  .fontSize(11)
                  .fontColor(this.autoScroll ? $r('app.color.veil_teal') :
                    $r('app.color.veil_text_faint'))
                  .onClick(() => {
                    this.autoScroll = !this.autoScroll;
                  })
              }
              .width('100%')

              Row({ space: 6 }) {
                Chip({
                  label: '全部', active: this.logLevel.length === 0,
                  tone: this.dark ? '#5EEAD4' : '#0E9F8E',
                  onTap: () => {
                    this.applyLogLevelFilter('');
                  }
                })
                Chip({
                  label: 'info', active: this.logLevel === 'info',
                  tone: this.dark ? '#5EEAD4' : '#0E9F8E',
                  onTap: () => {
                    this.applyLogLevelFilter('info');
                  }
                })
                Chip({
                  label: 'warn', active: this.logLevel === 'warn',
                  tone: this.dark ? '#FBBF24' : '#D97706',
                  onTap: () => {
                    this.applyLogLevelFilter('warn');
                  }
                })
                Chip({
                  label: 'error', active: this.logLevel === 'error',
                  tone: this.dark ? '#F87171' : '#DC2626',
                  onTap: () => {
                    this.applyLogLevelFilter('error');
                  }
                })
              }
              .width('100%')

              List({ space: 0, scroller: this.logScroller }) {
                ForEach(this.logLines, (line: LogLine) => {
                  ListItem() {
                    Row({ space: 8 }) {
                      Text(formatClock(line.time))
                        .fontSize(10)
                        .fontColor($r('app.color.veil_text_faint'))
                        .fontFeature('"tnum" 1')
                      Text(line.level)
                        .fontSize(10)
                        .fontColor(this.levelTone(line.level))
                        .width(38)
                      Text(line.msg)
                        .fontSize(11)
                        .fontColor($r('app.color.veil_text_dim'))
                        .layoutWeight(1)
                        .maxLines(4)
                    }
                    .width('100%')
                    .alignItems(VerticalAlign.Top)
                    .padding({ top: 4, bottom: 4 })
                  }
                }, (line: LogLine) => line.id.toString())
              }
              .width('100%')
              .height(220)
              .padding(10)
              .borderRadius(14)
              .backgroundColor($r('app.color.veil_surface_alt'))
              .scrollBar(BarState.Auto)
            }
            .width('100%')
            .padding(16)
            .borderRadius(20)
            .backgroundColor($r('app.color.veil_surface'))
            .border({ width: 0.5, color: $r('app.color.veil_hairline') })

            // ---- about ----------------------------------------------------
            Column({ space: 0 }) {
              SectionTitle({ title: '关于' })
              KeyValueRow({ label: '版本', value: this.version.length > 0 ? this.version : '未知' })
              Hairline()
              KeyValueRow({
                label: '构建',
                value: this.commit.length > 0 ? this.commit : '本地构建'
              })
              Hairline()
              KeyValueRow({ label: '核心状态', value: this.loaded ? '已读取配置' : '读取中' ,
                tone: this.loaded ? (this.dark ? '#34D399' : '#059669') :
                  (this.dark ? '#8B94A5' : '#5B6474') })
              Hairline()
              Row() {
                Text('Kitsune is a proxy client that tells the truth about its state.')
                  .fontSize(11)
                  .fontColor($r('app.color.veil_text_faint'))
                  .layoutWeight(1)
              }
              .width('100%')
              .padding({ top: 12 })
            }
            .width('100%')
            .padding(16)
            .borderRadius(20)
            .backgroundColor($r('app.color.veil_surface'))
            .border({ width: 0.5, color: $r('app.color.veil_hairline') })

            Column().height(24)
          }
          .width('100%')
          .padding({ left: 18, right: 18, top: 8 })
        }
        .scrollBar(BarState.Off)
        .edgeEffect(EdgeEffect.Spring)
        .width('100%')
        .height('100%')
      }
    }
    .width('100%')
    .height('100%')
    .onVisibleAreaChange([0.0, 1.0], (isVisible: boolean, ratio: number) => {
      if (isVisible && ratio > 0) {
        if (this.coreReady) {
          this.start();
        }
      } else {
        this.stop();
      }
    })
  }
}

/**
 * Deep-ish copy of the config so a failed `set_config` never leaves the UI
 * showing values the core rejected. Arrays are rebuilt; nested tun/dns objects
 * are re-created field by field.
 */
function cloneConfig(src: VeilConfig): VeilConfig {
  const tun = src.tun;
  const dns = src.dns;
  const copy: VeilConfig = {
    version: src.version,
    log_level: src.log_level,
    mode: src.mode,
    mixed: src.mixed,
    api: src.api,
    tun: {
      mtu: tun.mtu,
      ipv4: tun.ipv4,
      ipv6: tun.ipv6,
      dns: tun.dns,
      auto_route: tun.auto_route,
      bypass_lan: tun.bypass_lan,
      routes: tun.routes,
      bypass_apps: tun.bypass_apps,
      allow_apps: tun.allow_apps
    },
    dns: {
      enable: dns.enable,
      listen: dns.listen,
      servers: dns.servers,
      final: dns.final,
      cache: dns.cache
    },
    nodes: src.nodes.slice(),
    groups: src.groups.slice(),
    rules: src.rules.slice(),
    subscriptions: src.subscriptions.slice()
  };
  return copy;
}
