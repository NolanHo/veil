import { CoreClient } from '../core/CoreClient';
import { K_MODE, K_STATUS, Store } from '../core/Store';
import { formatDateTime } from '../core/Format';
import { ImportResult, NodeStatus, Phase, Rule, Status, Subscription, VeilConfig } from '../model/Types';
import { EmptyBlock, Hairline, SectionTitle, Tag } from './Ui';
import { Chip } from './Ui';
import { errorText, toast } from './Common';

/**
 * 规则 — routing mode, the ordered rule table, subscription maintenance and the
 * import sheet.
 *
 * The rule list is read-only here on purpose: rules come from the config the
 * core owns, and hand-editing them in a phone UI is how people lock themselves
 * out of the internet. Import, subscriptions and mode are the supported levers.
 */
@Component
export struct RulesView {
  @StorageProp('veilDark') dark: boolean = true;
  @Link @Watch('onCoreReady') coreReady: boolean;
  @StorageProp(K_MODE) mode: string = 'rule';
  @State rules: Rule[] = [];
  @State subs: Subscription[] = [];
  @State loaded: boolean = false;
  @State busyName: string = '';

  // import sheet
  @State showImport: boolean = false;
  @State pasteText: string = '';
  @State subName: string = '';
  @State subUrl: string = '';
  @State resultLine: string = '';
  @State resultErrors: string[] = [];

  aboutToAppear(): void {
    if (this.coreReady) {
      this.load();
    }
  }

  onCoreReady(): void {
    if (this.coreReady) {
      this.load();
    }
  }

  private async load(): Promise<void> {
    if (!this.coreReady) {
      return;
    }
    try {
      const cfg: VeilConfig = await CoreClient.get().config();
      AppStorage.setOrCreate(K_MODE, cfg.mode);
      this.rules = cfg.rules;
      this.subs = cfg.subscriptions;
      this.loaded = true;
    } catch (err) {
      toast(errorText(err));
    }
  }

  private async switchMode(mode: string): Promise<void> {
    if (mode === this.mode) {
      return;
    }
    // Optimistic: the chip highlights instantly; Store rolls back on failure.
    try {
      await Store.get().setMode(mode);
      const st: Status = AppStorage.get<Status>(K_STATUS) as Status;
      const live: boolean = st !== undefined && st !== null && Phase.isActive(st.phase);
      toast(live ? '分流模式已切换' : '分流模式已保存，连接后生效');
    } catch (err) {
      toast(errorText(err));
    }
  }

  private actionTone(action: string): string {
    if (action === 'direct') {
      return this.dark ? '#8B94A5' : '#5B6474';
    }
    if (action === 'reject') {
      return this.dark ? '#F87171' : '#DC2626';
    }
    return this.dark ? '#5EEAD4' : '#0E9F8E';
  }

  private async updateSub(name: string): Promise<void> {
    if (this.busyName.length > 0) {
      return;
    }
    this.busyName = name;
    try {
      const nodes: NodeStatus[] = await CoreClient.get().subUpdate(name);
      toast('订阅已更新，节点 ' + nodes.length.toString() + ' 个');
      await this.load();
    } catch (err) {
      toast(errorText(err));
    }
    this.busyName = '';
  }

  private async deleteSub(name: string): Promise<void> {
    try {
      await CoreClient.get().subDelete(name);
      toast('已删除订阅 ' + name);
      await this.load();
    } catch (err) {
      toast(errorText(err));
    }
  }

  private async doImport(): Promise<void> {
    const text: string = this.pasteText.trim();
    if (text.length === 0) {
      toast('请先粘贴节点或订阅内容');
      return;
    }
    try {
      const r: ImportResult = await CoreClient.get().importText(text);
      // Old cores do not report group/rule counts; treat absent as 0 so the
      // line never reads "分组 undefined".
      const groups: number = r.groups === undefined ? 0 : r.groups;
      const rules: number = r.rules === undefined ? 0 : r.rules;
      this.resultLine = '新增 ' + r.added.toString() + ' · 更新 ' + r.updated.toString() +
        ' · 失败 ' + r.failed.toString() + ' · 分组 ' + groups.toString() +
        ' · 规则 ' + rules.toString();
      this.resultErrors = r.errors === undefined ? [] : r.errors;
      this.pasteText = '';
      await this.load();
    } catch (err) {
      this.resultLine = '';
      this.resultErrors = [errorText(err)];
    }
  }

  private async addSub(): Promise<void> {
    const url: string = this.subUrl.trim();
    if (url.length === 0) {
      toast('请填写订阅地址');
      return;
    }
    const name: string = this.subName.trim().length > 0 ? this.subName.trim() : ('订阅 ' +
      (this.subs.length + 1).toString());
    try {
      await CoreClient.get().subAdd(name, url);
      this.subName = '';
      this.subUrl = '';
      this.resultLine = '订阅已添加: ' + name;
      await this.load();
    } catch (err) {
      this.resultErrors = [errorText(err)];
    }
  }

  @Builder
  importSheet() {
    Column({ space: 14 }) {
      Text('导入节点')
        .fontSize(17)
        .fontWeight(FontWeight.Medium)
        .fontColor($r('app.color.veil_text'))
        .width('100%')
        .textAlign(TextAlign.Start)

      Text('支持 vless:// vmess:// trojan:// ss:// hysteria2:// 分享链接（每行一条）、base64 订阅正文、Clash YAML、JSON 配置。')
        .fontSize(11)
        .fontColor($r('app.color.veil_text_faint'))
        .width('100%')
        .textAlign(TextAlign.Start)

      TextArea({ text: $$this.pasteText, placeholder: '在此粘贴…' })
        .width('100%')
        .height(150)
        .fontSize(12)
        .fontColor($r('app.color.veil_text'))
        .placeholderColor($r('app.color.veil_text_faint'))
        .backgroundColor($r('app.color.veil_surface_alt'))
        .borderRadius(14)
        .padding(12)

      Button('粘贴导入')
        .width('100%')
        .height(42)
        .fontSize(14)
        .backgroundColor($r('app.color.veil_teal'))
        .fontColor($r('app.color.veil_bg'))
        .borderRadius(14)
        .onClick(() => {
          this.doImport();
        })

      if (this.resultLine.length > 0) {
        Text(this.resultLine)
          .fontSize(12)
          .fontColor($r('app.color.veil_teal'))
          .width('100%')
          .textAlign(TextAlign.Start)
      }

      if (this.resultErrors.length > 0) {
        Column({ space: 4 }) {
          ForEach(this.resultErrors, (e: string) => {
            Text(e)
              .fontSize(11)
              .fontColor($r('app.color.veil_err'))
              .width('100%')
              .textAlign(TextAlign.Start)
          }, (e: string, idx: number) => idx.toString() + e)
        }
        .width('100%')
        .padding(10)
        .borderRadius(10)
        .backgroundColor($r('app.color.veil_surface_alt'))
      }

      Hairline()

      Text('添加订阅')
        .fontSize(13)
        .fontColor($r('app.color.veil_text_dim'))
        .width('100%')
        .textAlign(TextAlign.Start)

      TextInput({ text: $$this.subName, placeholder: '订阅名称（可留空）' })
        .width('100%')
        .height(40)
        .fontSize(13)
        .backgroundColor($r('app.color.veil_surface_alt'))
        .borderRadius(12)
        .padding({ left: 12, right: 12 })

      Row({ space: 10 }) {
        TextInput({ text: $$this.subUrl, placeholder: 'https://…' })
          .layoutWeight(1)
          .height(40)
          .fontSize(13)
          .backgroundColor($r('app.color.veil_surface_alt'))
          .borderRadius(12)
          .padding({ left: 12, right: 12 })

        Button('添加')
          .height(40)
          .fontSize(13)
          .backgroundColor($r('app.color.veil_surface_alt'))
          .fontColor($r('app.color.veil_teal'))
          .borderRadius(12)
          .onClick(() => {
            this.addSub();
          })
      }
      .width('100%')

      Blank()
    }
    .width('100%')
    .padding({ left: 20, right: 20, top: 10 })
  }

  @Builder
  ruleRow(rule: Rule, index: number) {
    Row({ space: 10 }) {
      Text((index + 1).toString())
        .fontSize(10)
        .fontColor($r('app.color.veil_text_faint'))
        .width(20)
        .textAlign(TextAlign.Start)
        .fontFeature('"tnum" 1')

      Column({ space: 3 }) {
        Text(rule.type)
          .fontSize(10)
          .fontColor($r('app.color.veil_text_dim'))
        Row({ space: 6 }) {
          Text(rule.value.length > 0 ? rule.value : '（任意）')
            .fontSize(13)
            .fontColor($r('app.color.veil_text'))
            .maxLines(1)
            .textOverflow({ overflow: TextOverflow.Ellipsis })
            .layoutWeight(1)
            .textAlign(TextAlign.Start)
          if (rule.no_resolve === true) {
            // A flag, not a routing decision: keep it quiet and out of the
            // action colour so it reads as an annotation on the value.
            Tag({ label: 'no-resolve', tone: this.dark ? '#8B94A5' : '#5B6474' })
          }
        }
        .width('100%')
        .alignItems(VerticalAlign.Center)
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)

      Tag({ label: rule.action, tone: this.actionTone(rule.action) })
    }
    .width('100%')
    .padding({ top: 9, bottom: 9 })
    .alignItems(VerticalAlign.Center)
  }

  @Builder
  subRow(sub: Subscription) {
    Row({ space: 10 }) {
      Column({ space: 3 }) {
        Text(sub.name)
          .fontSize(13)
          .fontColor($r('app.color.veil_text'))
          .width('100%')
          .textAlign(TextAlign.Start)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        Text(sub.url)
          .fontSize(10)
          .fontColor($r('app.color.veil_text_faint'))
          .width('100%')
          .textAlign(TextAlign.Start)
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
        Text('更新于 ' + formatDateTime(sub.updated === undefined ? 0 : sub.updated))
          .fontSize(10)
          .fontColor($r('app.color.veil_text_faint'))
          .width('100%')
          .textAlign(TextAlign.Start)
      }
      .layoutWeight(1)
      .alignItems(HorizontalAlign.Start)

      Text(this.busyName === sub.name ? '更新中' : '更新')
        .fontSize(12)
        .fontColor($r('app.color.veil_teal'))
        .padding({ left: 10, right: 10, top: 5, bottom: 5 })
        .borderRadius(8)
        .border({ width: 0.5, color: $r('app.color.veil_hairline') })
        .onClick(() => {
          this.updateSub(sub.name);
        })

      Text('删除')
        .fontSize(12)
        .fontColor($r('app.color.veil_err'))
        .padding({ left: 8, right: 4, top: 5, bottom: 5 })
        .onClick(() => {
          this.deleteSub(sub.name);
        })
    }
    .width('100%')
    .padding({ top: 10, bottom: 10 })
    .alignItems(VerticalAlign.Center)
  }

  build() {
    Column() {
      if (!this.coreReady) {
        EmptyBlock({
          title: '核心不可用',
          subtitle: '规则与订阅保存在核心的配置里，未连接时无法编辑。'
        })
      } else {
        Scroll() {
          Column({ space: 14 }) {
            // mode
            Column({ space: 10 }) {
              Row() {
                Text('分流模式')
                  .fontSize(13)
                  .fontColor($r('app.color.veil_text_dim'))
                Blank()
                Text(this.mode === 'rule' ? '按规则表匹配' : (this.mode === 'global' ? '全部走代理' : '全部直连'))
                  .fontSize(11)
                  .fontColor($r('app.color.veil_text_faint'))
              }
              .width('100%')

              Row({ space: 8 }) {
                Chip({
                  label: '规则', active: this.mode === 'rule', tone: this.dark ? '#5EEAD4' : '#0E9F8E',
                  onTap: () => {
                    this.switchMode('rule');
                  }
                })
                Chip({
                  label: '全局', active: this.mode === 'global', tone: this.dark ? '#5EEAD4' : '#0E9F8E',
                  onTap: () => {
                    this.switchMode('global');
                  }
                })
                Chip({
                  label: '直连', active: this.mode === 'direct', tone: this.dark ? '#5EEAD4' : '#0E9F8E',
                  onTap: () => {
                    this.switchMode('direct');
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

            // rules
            Column({ space: 0 }) {
              SectionTitle({ title: '规则表 · ' + this.rules.length.toString() + ' 条' })
              if (this.rules.length === 0) {
                Text('暂无规则，所有流量将按默认动作处理。')
                  .fontSize(12)
                  .fontColor($r('app.color.veil_text_faint'))
                  .padding({ top: 10, bottom: 10 })
                  .width('100%')
                  .textAlign(TextAlign.Start)
              } else {
                ForEach(this.rules, (rule: Rule, index: number) => {
                  this.ruleRow(rule, index)
                  Hairline()
                }, (rule: Rule, index: number) => index.toString() + rule.type + rule.value)
              }
            }
            .width('100%')
            .padding(16)
            .borderRadius(20)
            .backgroundColor($r('app.color.veil_surface'))
            .border({ width: 0.5, color: $r('app.color.veil_hairline') })

            // subscriptions
            Column({ space: 0 }) {
              Row() {
                Text('订阅 · ' + this.subs.length.toString())
                  .fontSize(13)
                  .fontWeight(FontWeight.Medium)
                  .fontColor($r('app.color.veil_text_dim'))
                Blank()
                Text('导入')
                  .fontSize(12)
                  .fontColor($r('app.color.veil_teal'))
                  .padding({ left: 10, right: 10, top: 5, bottom: 5 })
                  .borderRadius(8)
                  .border({ width: 0.5, color: $r('app.color.veil_hairline') })
                  .onClick(() => {
                    this.showImport = true;
                  })
              }
              .width('100%')
              .padding({ top: 4, bottom: 4 })

              if (this.subs.length === 0) {
                Text('还没有订阅。点击「导入」粘贴节点或添加订阅地址。')
                  .fontSize(12)
                  .fontColor($r('app.color.veil_text_faint'))
                  .padding({ top: 10, bottom: 10 })
                  .width('100%')
                  .textAlign(TextAlign.Start)
              } else {
                ForEach(this.subs, (sub: Subscription) => {
                  this.subRow(sub)
                  Hairline()
                }, (sub: Subscription) => sub.name)
              }
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
        .bindSheet($$this.showImport, this.importSheet(), {
          height: SheetSize.LARGE,
          dragBar: true,
          maskColor: '#99000000'
        })
      }
    }
    .width('100%')
    .height('100%')
    .onVisibleAreaChange([0.0, 1.0], (isVisible: boolean, ratio: number) => {
      if (isVisible && ratio > 0 && this.coreReady && !this.loaded) {
        this.load();
      }
    })
  }
}
