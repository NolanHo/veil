/**
 * Veil 桌面卡片（2*2 / 2*4）。
 *
 * 2*2 内集成：状态、当前节点（点击轮换）、代理模式（规则/全局/直连）、连接开关。
 * 数据由 VeilCardAbility 通过 formBindingData 注入；交互全部走 postCardAction
 * message 事件，由扩展进程去调 core。卡片不轮询、不常驻。
 */
@Entry
@Component
struct VeilCard {
  @LocalStorageProp('phase') phase: string = 'stopped';
  @LocalStorageProp('connected') connected: boolean = false;
  @LocalStorageProp('node') node: string = '未选择节点';
  @LocalStorageProp('downRate') downRate: string = '—';
  @LocalStorageProp('upRate') upRate: string = '—';
  @LocalStorageProp('stateLabel') stateLabel: string = '未连接';
  @LocalStorageProp('accent') accent: string = '#5EEAD4';
  @LocalStorageProp('mode') mode: string = 'rule';
  @LocalStorageProp('nodeCount') nodeCount: number = 0;

  private modePill(label: string, value: string): void {
    // shared pill builder is not allowed in cards; keep the layout inline instead
  }

  build() {
    Column() {
      // ---- status ------------------------------------------------------
      Row() {
        Row({ space: 5 }) {
          Circle()
            .width(6)
            .height(6)
            .fill(this.accent)
            .shadow({ radius: 6, color: this.accent })
          Text(this.stateLabel)
            .fontSize(11)
            .fontWeight(FontWeight.Medium)
            .fontColor(this.accent)
            .maxLines(1)
        }

        Blank()

        Text('KITSUNE')
          .fontSize(9)
          .fontColor('#475569')
          .letterSpacing(2)
      }
      .width('100%')

      // ---- node (tap to rotate) ----------------------------------------
      Row({ space: 4 }) {
        Text(this.node)
          .fontSize(13)
          .fontWeight(FontWeight.Medium)
          .fontColor('#E2E8F0')
          .maxLines(1)
          .textOverflow({ overflow: TextOverflow.Ellipsis })
          .layoutWeight(1)

        Text('⇄')
          .fontSize(13)
          .fontColor('#38BDF8')
      }
      .width('100%')
      .padding({ top: 6, bottom: 6 })
      .onClick(() => {
        postCardAction(this, {
          action: 'message',
          params: { event: 'nextNode' }
        });
      })

      // ---- rates -------------------------------------------------------
      Row() {
        Text('↓' + this.downRate)
          .fontSize(12)
          .fontWeight(FontWeight.Medium)
          .fontColor('#5EEAD4')
          .fontFeature('"tnum" 1')
        Blank()
        Text('↑' + this.upRate)
          .fontSize(12)
          .fontWeight(FontWeight.Medium)
          .fontColor('#818CF8')
          .fontFeature('"tnum" 1')
      }
      .width('100%')

      // ---- mode pills ---------------------------------------------------
      Row({ space: 4 }) {
        Text('规则')
          .fontSize(9)
          .fontColor(this.mode === 'rule' ? '#0B1220' : '#94A3B8')
          .backgroundColor(this.mode === 'rule' ? '#5EEAD4' : '#1E293B')
          .borderRadius(7)
          .padding({ left: 6, right: 6, top: 3, bottom: 3 })
          .layoutWeight(1)
          .textAlign(TextAlign.Center)
          .onClick(() => {
            postCardAction(this, { action: 'message', params: { event: 'mode:rule' } });
          })

        Text('全局')
          .fontSize(9)
          .fontColor(this.mode === 'global' ? '#0B1220' : '#94A3B8')
          .backgroundColor(this.mode === 'global' ? '#5EEAD4' : '#1E293B')
          .borderRadius(7)
          .padding({ left: 6, right: 6, top: 3, bottom: 3 })
          .layoutWeight(1)
          .textAlign(TextAlign.Center)
          .onClick(() => {
            postCardAction(this, { action: 'message', params: { event: 'mode:global' } });
          })

        Text('直连')
          .fontSize(9)
          .fontColor(this.mode === 'direct' ? '#0B1220' : '#94A3B8')
          .backgroundColor(this.mode === 'direct' ? '#5EEAD4' : '#1E293B')
          .borderRadius(7)
          .padding({ left: 6, right: 6, top: 3, bottom: 3 })
          .layoutWeight(1)
          .textAlign(TextAlign.Center)
          .onClick(() => {
            postCardAction(this, { action: 'message', params: { event: 'mode:direct' } });
          })
      }
      .width('100%')
      .margin({ top: 6 })

      Blank()

      // ---- power --------------------------------------------------------
      Text(this.connected ? '断开连接' : '连接')
        .fontSize(12)
        .fontWeight(FontWeight.Medium)
        .fontColor(this.connected ? '#FCA5A5' : '#0B1220')
        .backgroundColor(this.connected ? '#3F1D24' : '#5EEAD4')
        .borderRadius(10)
        .height(28)
        .width('100%')
        .textAlign(TextAlign.Center)
        .margin({ top: 6 })
        .onClick(() => {
          postCardAction(this, {
            action: 'message',
            params: { event: this.connected ? 'stop' : 'start' }
          });
        })
    }
    .width('100%')
    .height('100%')
    .padding(12)
    .linearGradient({
      angle: 160,
      colors: [['#0B1220', 0.0], ['#111C33', 0.55], ['#0B1220', 1.0]]
    })
    .borderRadius(16)
    .border({ width: 0.5, color: '#1E3A5F' })
    .alignItems(HorizontalAlign.Start)
  }
}
