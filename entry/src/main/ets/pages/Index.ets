import { mediaquery } from '@kit.ArkUI';
import { CoreClient, CoreState } from '../core/CoreClient';
import { Store } from '../core/Store';
import { Status } from '../model/Types';
import { coreStateLabel } from '../views/Common';
import { Glyph } from '../views/Glyph';
import { themeOf, ThemeColors } from '../theme/Theme';
import { HomeView } from '../views/HomeView';
import { NodesView } from '../views/NodesView';
import { RulesView } from '../views/RulesView';
import { SettingsView } from '../views/SettingsView';

/** Glyph kinds per tab: drawn on a Canvas, not an icon font, not emoji. */
const ICONS: string[] = ['link', 'nodes', 'rules', 'settings'];

const TAB_LABELS: string[] = ['连接', '节点', '规则', '设置'];

/**
 * Single @Entry page: a header that reports the *core link* (not the tunnel),
 * an availability banner, and the four tab screens.
 *
 * Deliberately the only place that owns the "is the core reachable" bit; every
 * tab takes it as a @Link so nothing renders stale "connected" chrome after the
 * socket dies.
 */
@Entry
@Component
struct Index {
  @State coreReady: boolean = false;
  @State coreState: CoreState = CoreState.Idle;
  @State tabSelection: number = 0;
  @State retrying: boolean = false;
  @StorageProp('veilDark') dark: boolean = true;

  private listener: mediaquery.MediaQueryListener | null = null;
  private controller: TabsController = new TabsController();


  private onCoreState: (s: CoreState) => void = (s: CoreState) => {
    this.coreState = s;
    this.coreReady = s === CoreState.Ready;
  };

  aboutToAppear(): void {
    const mq: mediaquery.MediaQueryListener = mediaquery.matchMediaSync('(dark-mode: true)');
    this.listener = mq;
    AppStorage.setOrCreate('veilDark', mq.matches);
    mq.on('change', (result: mediaquery.MediaQueryResult) => {
      AppStorage.setOrCreate('veilDark', result.matches);
    });

    CoreClient.get().onState(this.onCoreState);
    this.coreState = CoreClient.get().getState();
    this.bootstrap();
  }

  aboutToDisappear(): void {
    CoreClient.get().offState(this.onCoreState);
    const mq: mediaquery.MediaQueryListener | null = this.listener;
    if (mq !== null) {
      mq.off('change');
      this.listener = null;
    }
  }

  private async bootstrap(): Promise<void> {
    const ok: boolean = await CoreClient.get().bootstrap();
    this.coreReady = ok;
    this.coreState = CoreClient.get().getState();
    if (ok) {
      // Warm the shared snapshot immediately so a freshly added card renders
      // the selected node instead of "未选择节点" until the first tap.
      const st: Status | null = await Store.get().refresh();
      if (st !== null) {
        await Store.get().pushCards(st);
      }
    }
  }

  private async retry(): Promise<void> {
    if (this.retrying) {
      return;
    }
    this.retrying = true;
    const ok: boolean = await CoreClient.get().reconnect();
    this.coreReady = ok;
    this.coreState = CoreClient.get().getState();
    this.retrying = false;
  }

  @Builder
  tabItem(index: number, label: string) {
    Column({ space: 4 }) {
      Glyph({
        kind: ICONS[index],
        tint: this.tabSelection === index ? themeOf(this.dark).teal : themeOf(this.dark).textFaint,
        dim: 22,
        weight: 1.5
      })

      Text(label)
        .fontSize(10)
        .fontColor(this.tabSelection === index ?
          $r('app.color.veil_text') : $r('app.color.veil_text_faint'))
    }
    .width('100%')
    .height(54)
    .justifyContent(FlexAlign.Center)
  }

  @Builder
  header() {
    Row() {
      Column({ space: 2 }) {
        Text('Kitsune')
          .fontSize(20)
          .fontWeight(FontWeight.Medium)
          .fontColor($r('app.color.veil_text'))
          .letterSpacing(2)

        Text('本地核心 · 独立 VPN 进程')
          .fontSize(10)
          .fontColor($r('app.color.veil_text_faint'))
      }
      .alignItems(HorizontalAlign.Start)

      Blank()

      Row({ space: 5 }) {
        Circle()
          .width(5)
          .height(5)
          .fill(this.coreReady ? $r('app.color.veil_ok') : $r('app.color.veil_warn'))
        Text(coreStateLabel(this.coreState))
          .fontSize(10)
          .fontColor($r('app.color.veil_text_dim'))
      }
      .padding({ left: 10, right: 10, top: 6, bottom: 6 })
      .borderRadius(10)
      .backgroundColor($r('app.color.veil_surface_alt'))
    }
    .width('100%')
    .padding({ left: 18, right: 18, top: 8, bottom: 8 })
    .alignItems(VerticalAlign.Center)
  }

  @Builder
  offlineBanner() {
    Row({ space: 10 }) {
      Column({ space: 2 }) {
        Text('核心不可用')
          .fontSize(12)
          .fontWeight(FontWeight.Medium)
          .fontColor($r('app.color.veil_text'))
        Text(CoreClient.get().getLastError().length > 0 ?
          CoreClient.get().getLastError() : '正在等待 VPN 扩展进程就绪')
          .fontSize(10)
          .fontColor($r('app.color.veil_text_faint'))
          .maxLines(2)
      }
      .alignItems(HorizontalAlign.Start)
      .layoutWeight(1)

      Text(this.retrying ? '连接中' : '重试')
        .fontSize(12)
        .fontColor($r('app.color.veil_teal'))
        .padding({ left: 12, right: 12, top: 6, bottom: 6 })
        .borderRadius(10)
        .border({ width: 0.5, color: $r('app.color.veil_hairline') })
        .onClick(() => {
          this.retry();
        })
    }
    .width('100%')
    .padding(12)
    .margin({ left: 18, right: 18, bottom: 6 })
    .borderRadius(14)
    .backgroundColor($r('app.color.veil_surface_alt'))
    .border({ width: 0.5, color: $r('app.color.veil_hairline') })
  }

  build() {
    Column() {
      this.header()

      if (!this.coreReady) {
        this.offlineBanner()
      }

      Tabs({ barPosition: BarPosition.End, index: this.tabSelection, controller: this.controller }) {
        TabContent() {
          HomeView({ coreReady: $coreReady })
        }
        .tabBar(this.tabItem(0, TAB_LABELS[0]))

        TabContent() {
          NodesView({ coreReady: $coreReady })
        }
        .tabBar(this.tabItem(1, TAB_LABELS[1]))

        TabContent() {
          RulesView({ coreReady: $coreReady })
        }
        .tabBar(this.tabItem(2, TAB_LABELS[2]))

        TabContent() {
          SettingsView({ coreReady: $coreReady })
        }
        .tabBar(this.tabItem(3, TAB_LABELS[3]))
      }
      .barMode(BarMode.Fixed)
      .barHeight(54)
      .barBackgroundColor($r('app.color.veil_surface'))
      .divider({ strokeWidth: 0.5, color: $r('app.color.veil_hairline') })
      .scrollable(false)
      .animationDuration(180)
      .layoutWeight(1)
      .onChange((index: number) => {
        this.tabSelection = index;
      })
    }
    .width('100%')
    .height('100%')
    .backgroundColor($r('app.color.veil_bg'))
  }
}
