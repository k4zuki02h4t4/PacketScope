//! PacketScope — per-application packet capture viewer.
//!
//! Three panes, following the design mockups: applications (left,
//! fixed), the selected app's capture history (middle), and the
//! selected flow's payload detail (right). Dark and light themes.
//! Packet capture only: no proxy, no MITM.

// No console window on Windows: GUI-subsystem binary. (The embedded
// manifest additionally requests elevation at launch.)
#![cfg_attr(windows, windows_subsystem = "windows")]

use netwatch::model::{Content, Flow, FlowKey, Settings};
use netwatch::{engine, icons};

use iced::widget::canvas::{self, Canvas};
use iced::widget::image::{Handle as ImageHandle, Image};
use iced::widget::{button, column, container, mouse_area, row, scrollable, stack, text, text_input, Column};
use iced::{mouse, Border, Color, Element, Length, Point, Rectangle, Renderer, Subscription, Task, Theme};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Bundled Japanese font (Noto Sans JP, OFL 1.1). iced's default font has
/// no CJK glyphs, which is why the first build showed tofu boxes.
static NOTO_SANS_JP: &[u8] = include_bytes!("../assets/NotoSansJP.ttf");

/// App icon (design M2: open scope ring, waveform, packets), also
/// embedded into the .exe as a resource by build.rs. This sets the
/// runtime window / taskbar icon.
static APP_ICON_PNG: &[u8] = include_bytes!("../assets/app-icon.png");

fn window_icon() -> Option<iced::window::Icon> {
    let decoder = png::Decoder::new(std::io::Cursor::new(APP_ICON_PNG));
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    buf.truncate(info.buffer_size());
    if info.color_type != png::ColorType::Rgba {
        return None;
    }
    iced::window::icon::from_rgba(buf, info.width, info.height).ok()
}

/// Last-resort crash log. This is a GUI-subsystem binary, so a panic
/// normally kills the app silently (the window just disappears, which is
/// what the v1.1.0 Headers-tab crash looked like). Append the panic and a
/// backtrace to crash.log in the data directory so a failure leaves
/// evidence that can be sent in with a bug report.
fn install_crash_log() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let dir = data_dir();
        let _ = std::fs::create_dir_all(&dir);
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic payload".to_string()
        };
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());
        let entry = format!(
            "\n=== {} ===\npanic: {msg}\nat: {loc}\nbacktrace:\n{}\n",
            fmt_full(SystemTime::now()),
            std::backtrace::Backtrace::force_capture()
        );
        let log_path = dir.join("crash.log");
        remove_if_reparse(&log_path);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            use std::io::Write;
            let _ = f.write_all(entry.as_bytes());
        }
        default_hook(info);
    }));
}

fn main() -> iced::Result {
    install_crash_log();
    let args: Vec<String> = std::env::args().collect();
    // The manifest asks Windows for elevation, but some launch routes
    // still start this binary without an administrator token (seen in
    // the field: launched directly, the uninstaller could neither
    // start Npcap's uninstaller — error 740 — nor delete files under
    // Program Files — error 5 — while the same binary launched from
    // Settings > Apps ran elevated and everything worked). Secure the
    // token ourselves: if not elevated, relaunch via ShellExecute
    // "runas" once and exit. If the user declines the UAC prompt,
    // that is a deliberate choice — exit silently instead of nagging
    // with an explanation dialog (field feedback, v1.2.8). Only a
    // relaunch that failed outright, or a retry that still came back
    // without a token, gets the explanation.
    #[cfg(windows)]
    if !is_elevated() {
        if !args.iter().any(|a| a == "--elevated-retry") {
            match relaunch_elevated(&args) {
                Relaunch::Started | Relaunch::Cancelled => return Ok(()),
                Relaunch::Failed => {}
            }
        }
        netwatch::system_setup::info_box(
            "PacketScope の実行には管理者権限が必要です。\nUAC の確認画面で「はい」を選ぶか、管理者として実行してください。",
            "PacketScope",
        );
        return Ok(());
    }
    // Cleanup helper mode: the uninstaller copies this binary to
    // %TEMP% and relaunches it with --cleanup-helper to remove the
    // install folder after the uninstaller itself has exited.
    if args.iter().any(|a| a == "--cleanup-helper") {
        cleanup_helper(&args);
        return Ok(());
    }
    // Full uninstall: when this binary runs as uninstall.exe (the setup
    // program places a copy under that name) or with --uninstall-app.
    let exe_stem = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    if args.iter().any(|a| a == "--uninstall-app") || exe_stem.starts_with("uninstall") {
        uninstall_app();
        return Ok(());
    }
    let result = iced::application("PacketScope", App::update, App::view)
        .theme(|app: &App| if app.settings.theme_dark { Theme::Dark } else { Theme::Light })
        .font(std::borrow::Cow::Borrowed(NOTO_SANS_JP))
        .default_font(iced::Font::with_name("Noto Sans JP"))
        .window(iced::window::Settings {
            size: iced::Size::new(1440.0, 900.0),
            min_size: Some(iced::Size::new(1080.0, 620.0)),
            icon: window_icon(),
            ..Default::default()
        })
        .subscription(App::subscription)
        .run();
    // Stop the ETW kernel-logger session if we started one, so it
    // doesn't linger as an orphan after the window closes.
    netwatch::etw::shutdown();
    result
}

// ---------------------------------------------------------------- theme

#[derive(Debug, Clone, Copy)]
struct Pal {
    bg: Color,
    panel: Color,
    panel_alt: Color,
    border: Color,
    text: Color,
    sub: Color,
    faint: Color,
    accent: Color,
    sel_bg: Color,
    green: Color,
    orange: Color,
    red: Color,
}

fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::from_rgb8(r, g, b)
}

impl Pal {
    fn dark() -> Pal {
        Pal {
            bg: rgb(0x16, 0x16, 0x19),
            panel: rgb(0x1c, 0x1c, 0x1e),
            panel_alt: rgb(0x26, 0x26, 0x2a),
            border: rgb(0x2c, 0x2c, 0x30),
            text: rgb(0xf5, 0xf5, 0xf7),
            sub: rgb(0xa1, 0xa1, 0xa6),
            faint: rgb(0x8c, 0x8c, 0x93),
            accent: rgb(0x0a, 0x84, 0xff),
            sel_bg: rgb(0x0b, 0x2d, 0x59),
            green: rgb(0x32, 0xd7, 0x4b),
            orange: rgb(0xff, 0x9f, 0x0a),
            red: rgb(0xff, 0x45, 0x3a),
        }
    }
    fn light() -> Pal {
        Pal {
            bg: rgb(0xf6, 0xf6, 0xf8),
            panel: rgb(0xff, 0xff, 0xff),
            panel_alt: rgb(0xf1, 0xf1, 0xf4),
            border: rgb(0xe2, 0xe2, 0xe6),
            text: rgb(0x1d, 0x1d, 0x1f),
            sub: rgb(0x6e, 0x6e, 0x73),
            faint: rgb(0x85, 0x85, 0x8c),
            accent: rgb(0x00, 0x71, 0xe3),
            sel_bg: rgb(0xe3, 0xef, 0xfd),
            green: rgb(0x1d, 0x9a, 0x4b),
            orange: rgb(0xb4, 0x5c, 0x00),
            red: rgb(0xde, 0x3a, 0x2f),
        }
    }
}

// ---------------------------------------------------------------- state

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirFilter {
    All,
    Sent,
    Received,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    Payload,
    Headers,
    Raw,
}

#[derive(Debug, Clone)]
enum Message {
    Tick,
    SearchChanged(String),
    SelectApp(String),
    SelectFlow(FlowKey),
    SetFilter(DirFilter),
    SetDetailTab(DetailTab),
    ToggleTheme,
    ToggleAppMenu,
    CloseAppMenu,
    OpenFileLocation,
}

/// Theme toggle icon, drawn as vectors. The previous text glyphs (sun /
/// moon characters) silently vanished when the loaded fonts had no glyph
/// for them — the moon in light mode was missing entirely. Shapes follow
/// the design mockups (Feather-style outlines in a 24x24 box): a crescent
/// moon in light mode, a sun in dark mode.
struct ThemeIcon {
    moon: bool,
    color: Color,
}

impl canvas::Program<Message> for ThemeIcon {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let s = bounds.width.min(bounds.height) / 24.0;
        let p = |x: f32, y: f32| Point::new(x * s, y * s);
        let stroke = canvas::Stroke::default()
            .with_color(self.color)
            .with_width(2.1 * s)
            .with_line_cap(canvas::LineCap::Round);
        // Polyline approximation of an arc (centre, radius, angle range).
        let arc = |cx: f32, cy: f32, r: f32, a0: f32, a1: f32, steps: usize| {
            canvas::Path::new(|b| {
                for i in 0..=steps {
                    let a = a0 + (a1 - a0) * (i as f32 / steps as f32);
                    let pt = p(cx + r * a.cos(), cy + r * a.sin());
                    if i == 0 {
                        b.move_to(pt);
                    } else {
                        b.line_to(pt);
                    }
                }
            })
        };
        if self.moon {
            // Crescent: outer edge B->A, then the inner bite B->A.
            frame.stroke(&arc(12.0, 12.0, 9.0, 0.087, 4.625, 48), stroke);
            frame.stroke(&arc(16.82, 7.18, 7.0, 0.932, 3.787, 32), stroke);
        } else {
            frame.stroke(&arc(12.0, 12.0, 4.0, 0.0, std::f32::consts::TAU, 32), stroke);
            let rays = canvas::Path::new(|b| {
                for (x1, y1, x2, y2) in [
                    (12.0, 1.0, 12.0, 3.0),
                    (12.0, 21.0, 12.0, 23.0),
                    (4.22, 4.22, 5.64, 5.64),
                    (18.36, 18.36, 19.78, 19.78),
                    (1.0, 12.0, 3.0, 12.0),
                    (21.0, 12.0, 23.0, 12.0),
                    (4.22, 19.78, 5.64, 18.36),
                    (18.36, 5.64, 19.78, 4.22),
                ] {
                    b.move_to(p(x1, y1));
                    b.line_to(p(x2, y2));
                }
            });
            frame.stroke(&rays, stroke);
        }
        vec![frame.into_geometry()]
    }
}

/// Three-dot "more" icon for the middle pane header, drawn as vectors
/// for the same reason as ThemeIcon (no font dependence).
struct DotsIcon {
    color: Color,
}

impl canvas::Program<Message> for DotsIcon {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let s = bounds.width.min(bounds.height) / 24.0;
        for cx in [5.0, 12.0, 19.0] {
            frame.fill(
                &canvas::Path::circle(Point::new(cx * s, 12.0 * s), 1.9 * s),
                self.color,
            );
        }
        vec![frame.into_geometry()]
    }
}

/// Padlock marker for decrypted flows in the history list, drawn as
/// vectors for the same reason as ThemeIcon: the shipped font stack
/// (bundled Noto Sans JP) has no U+1F513 glyph, so the lock-emoji text
/// marker added in v1.3.0 rendered as tofu on Windows (field
/// report). Feather-style lock outline in a 24x24 box: rounded body
/// rect, shackle arc, keyhole dot.
struct LockIcon {
    color: Color,
}

impl canvas::Program<Message> for LockIcon {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let s = bounds.width.min(bounds.height) / 24.0;
        let p = |x: f32, y: f32| Point::new(x * s, y * s);
        let stroke = canvas::Stroke::default()
            .with_color(self.color)
            .with_width(2.0 * s)
            .with_line_cap(canvas::LineCap::Round);
        // Body: rounded rect from (5,11) to (19,21), radius 2.
        let body = canvas::Path::new(|b| {
            b.move_to(p(7.0, 11.0));
            b.line_to(p(17.0, 11.0));
            b.arc_to(p(19.0, 11.0), p(19.0, 13.0), 2.0 * s);
            b.line_to(p(19.0, 19.0));
            b.arc_to(p(19.0, 21.0), p(17.0, 21.0), 2.0 * s);
            b.line_to(p(7.0, 21.0));
            b.arc_to(p(5.0, 21.0), p(5.0, 19.0), 2.0 * s);
            b.line_to(p(5.0, 13.0));
            b.arc_to(p(5.0, 11.0), p(7.0, 11.0), 2.0 * s);
            b.close();
        });
        frame.stroke(&body, stroke);
        // Shackle: arc over the top (centre 12,11, radius 4, upper half).
        let shackle = canvas::Path::new(|b| {
            for i in 0..=24 {
                let a = std::f32::consts::PI * (i as f32 / 24.0);
                let pt = p(12.0 - 4.0 * a.cos(), 11.0 - 4.0 * a.sin());
                if i == 0 {
                    b.move_to(pt);
                } else {
                    b.line_to(pt);
                }
            }
        });
        frame.stroke(&shackle, stroke);
        // Keyhole.
        frame.fill(&canvas::Path::circle(p(12.0, 16.0), 1.4 * s), self.color);
        vec![frame.into_geometry()]
    }
}

/// "Open file location": Explorer with the file selected (Windows),
/// Finder reveal (macOS), or the containing folder (Linux).
fn open_file_location(path: &str) {
    #[cfg(target_os = "windows")]
    {
        // Use the same Shell API Task Manager uses. The explorer.exe
        // /select command line proved unreliable (its parsing varies
        // with already-open windows and path contents), while
        // SHOpenFolderAndSelectItems always opens the containing folder
        // with the file selected.
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr::null_mut;
        use windows_sys::Win32::System::Com::CoInitializeEx;
        use windows_sys::Win32::UI::Shell::{
            ILClone, ILCreateFromPathW, ILFree, ILRemoveLastID, SHOpenFolderAndSelectItems,
        };
        let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
        let done = unsafe {
            let _ = CoInitializeEx(null_mut(), 2 /* COINIT_APARTMENTTHREADED */);
            let file_pidl = ILCreateFromPathW(wide.as_ptr());
            let mut ok = false;
            if !file_pidl.is_null() {
                let folder_pidl = ILClone(file_pidl);
                if !folder_pidl.is_null() {
                    ILRemoveLastID(folder_pidl);
                    let items: [*const windows_sys::Win32::UI::Shell::Common::ITEMIDLIST; 1] =
                        [file_pidl];
                    ok = SHOpenFolderAndSelectItems(folder_pidl, 1, items.as_ptr(), 0) >= 0;
                    ILFree(folder_pidl);
                }
                ILFree(file_pidl);
            }
            ok
        };
        if !done {
            // Fallback: Explorer command line (quoted /select form),
            // spawned by absolute path rather than by bare name.
            let explorer = std::env::var_os("SystemRoot")
                .map(|r| std::path::PathBuf::from(r).join("explorer.exe"))
                .unwrap_or_else(|| std::path::PathBuf::from("explorer"));
            let _ = std::process::Command::new(explorer)
                .arg(format!("/select,\"{path}\""))
                .spawn();
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg("-R").arg(path).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = std::path::Path::new(path).parent() {
            let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
        }
    }
}

struct App {
    settings: Settings,
    flows: Vec<Flow>,
    status: String,
    started: Instant,
    snap_rx: Receiver<(Vec<Flow>, Vec<netwatch::model::Alert>, String)>,
    search: String,
    filter: DirFilter,
    detail_tab: DetailTab,
    selected_app: Option<String>,
    selected_flow: Option<FlowKey>,
    app_menu_open: bool,
    icons: HashMap<String, Option<ImageHandle>>,
    icon_req_tx: Sender<String>,
    icon_rx: Receiver<(String, Option<Vec<u8>>)>,
    icon_pending: HashSet<String>,
}

struct AppAgg {
    key: String,
    name: String,
    path: String,
    path_estimate: bool,
    total: u64,
    sent: u64,
    received: u64,
    packets: u64,
    flow_count: usize,
}

fn app_key(f: &Flow) -> String {
    if f.process_path.is_empty() {
        format!("{}\u{1}", f.process_name)
    } else {
        format!("{}\u{1}{}", f.process_name, f.process_path)
    }
}

impl App {
    fn subscription(&self) -> Subscription<Message> {
        iced::time::every(std::time::Duration::from_millis(500)).map(|_| Message::Tick)
    }

    fn pal(&self) -> Pal {
        if self.settings.theme_dark {
            Pal::dark()
        } else {
            Pal::light()
        }
    }

    fn aggregates(&self) -> Vec<AppAgg> {
        let mut map: HashMap<String, AppAgg> = HashMap::new();
        for f in &self.flows {
            if self.settings.is_excluded(&f.process_name, &f.process_path) {
                continue;
            }
            let e = map.entry(app_key(f)).or_insert_with(|| AppAgg {
                key: app_key(f),
                name: if f.process_name.is_empty() {
                    "不明".to_string()
                } else {
                    f.process_name.clone()
                },
                path: f.process_path.clone(),
                path_estimate: f.path_estimate,
                total: 0,
                sent: 0,
                received: 0,
                packets: 0,
                flow_count: 0,
            });
            e.total += f.bytes_up + f.bytes_down;
            e.sent += f.bytes_up;
            e.received += f.bytes_down;
            e.packets += f.packets_up + f.packets_down;
            e.flow_count += 1;
        }
        let mut v: Vec<AppAgg> = map.into_values().collect();
        v.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.name.cmp(&b.name)));
        v
    }

    fn selected_flows(&self) -> Vec<&Flow> {
        let Some(sel) = &self.selected_app else {
            return Vec::new();
        };
        let mut v: Vec<&Flow> = self
            .flows
            .iter()
            .filter(|f| &app_key(f) == sel)
            .filter(|f| !self.settings.is_excluded(&f.process_name, &f.process_path))
            .filter(|f| match self.filter {
                DirFilter::All => true,
                DirFilter::Sent => f.bytes_up > 0,
                DirFilter::Received => f.bytes_down > 0,
            })
            .collect();
        v.sort_by(|a, b| b.first_seen.cmp(&a.first_seen));
        v
    }

    fn current_flow(&self) -> Option<&Flow> {
        let key = self.selected_flow.as_ref()?;
        self.flows.iter().find(|f| &f.key == key)
    }

    fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::Tick => {
                while let Ok((flows, _alerts, status)) = self.snap_rx.try_recv() {
                    self.flows = flows;
                    self.status = status;
                }
                while let Ok((path, png)) = self.icon_rx.try_recv() {
                    self.icon_pending.remove(&path);
                    self.icons.insert(
                        path,
                        png.map(|b| ImageHandle::from_bytes(b)),
                    );
                }
                // Request icons for apps we have not seen yet.
                let paths: Vec<String> = self
                    .aggregates()
                    .iter()
                    .map(|a| a.path.clone())
                    .filter(|p| !p.is_empty())
                    .collect();
                for p in paths {
                    if !self.icons.contains_key(&p) && !self.icon_pending.contains(&p) {
                        self.icon_pending.insert(p.clone());
                        let _ = self.icon_req_tx.send(p);
                    }
                }
                // Keep selection valid.
                if let Some(sel) = &self.selected_app {
                    if !self.flows.iter().any(|f| &app_key(f) == sel) {
                        self.selected_app = None;
                        self.selected_flow = None;
                    }
                }
                if self.selected_app.is_none() {
                    if let Some(first) = self.aggregates().into_iter().next() {
                        self.selected_app = Some(first.key);
                    }
                }
            }
            Message::SearchChanged(s) => self.search = s,
            Message::SelectApp(k) => {
                self.selected_app = Some(k);
                self.selected_flow = None;
                self.app_menu_open = false;
            }
            Message::SelectFlow(k) => self.selected_flow = Some(k),
            Message::SetFilter(f) => self.filter = f,
            Message::SetDetailTab(t) => self.detail_tab = t,
            Message::ToggleTheme => {
                self.settings.theme_dark = !self.settings.theme_dark;
                save_settings(&self.settings);
            }
            Message::ToggleAppMenu => self.app_menu_open = !self.app_menu_open,
            Message::CloseAppMenu => self.app_menu_open = false,
            Message::OpenFileLocation => {
                self.app_menu_open = false;
                if let Some(agg) = self
                    .selected_app
                    .as_ref()
                    .and_then(|k| self.aggregates().into_iter().find(|a| &a.key == k))
                {
                    if !agg.path.is_empty() {
                        open_file_location(&agg.path);
                    }
                }
            }
        }
        Task::none()
    }
}

// ---------------------------------------------------------------- boot

fn spawn_icon_worker() -> (Sender<String>, Receiver<(String, Option<Vec<u8>>)>) {
    let (req_tx, req_rx) = std::sync::mpsc::channel::<String>();
    let (res_tx, res_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut cache: HashMap<String, Option<Vec<u8>>> = HashMap::new();
        for path in req_rx {
            if let Some(v) = cache.get(&path) {
                if res_tx.send((path, v.clone())).is_err() {
                    return;
                }
                continue;
            }
            let png = icons::icon_png(&path);
            cache.insert(path.clone(), png.clone());
            if res_tx.send((path, png)).is_err() {
                return;
            }
        }
    });
    (req_tx, res_rx)
}

impl Default for App {
    fn default() -> Self {
        let settings = load_settings();
        let snap_rx = engine::spawn(settings.clone());
        let (icon_req_tx, icon_rx) = spawn_icon_worker();
        App {
            settings,
            flows: Vec::new(),
            status: "起動中…".to_string(),
            started: Instant::now(),
            snap_rx,
            search: String::new(),
            filter: DirFilter::All,
            detail_tab: DetailTab::Payload,
            selected_app: None,
            selected_flow: None,
            app_menu_open: false,
            icons: HashMap::new(),
            icon_req_tx,
            icon_rx,
            icon_pending: HashSet::new(),
        }
    }
}

// ---------------------------------------------------------------- view

impl App {
    fn view(&self) -> Element<'_, Message> {
        let pal = self.pal();
        let content = column![self.header(pal), self.panes(pal)]
            .width(Length::Fill)
            .height(Length::Fill);
        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(move |_| container::Style {
                background: Some(pal.bg.into()),
                text_color: Some(pal.text),
                ..Default::default()
            })
            .into()
    }

    fn header(&self, pal: Pal) -> Element<'_, Message> {
        let elapsed = self.started.elapsed().as_secs();
        let pill = container(
            row![
                text("●").size(9).color(pal.red),
                text("Recording").size(12.5).color(pal.red),
                text(format!("{:02}:{:02}:{:02}", elapsed / 3600, (elapsed / 60) % 60, elapsed % 60))
                    .size(12.5)
                    .color(pal.sub)
                    .font(iced::Font::MONOSPACE),
            ]
            .spacing(7)
            .align_y(iced::Alignment::Center),
        )
        .padding([5, 12])
        .style(move |_| container::Style {
            background: Some(Color::from_rgba(1.0, 0.27, 0.23, 0.13).into()),
            border: Border { radius: 999.0.into(), ..Default::default() },
            ..Default::default()
        });
        let theme_btn = button(
            Canvas::new(ThemeIcon { moon: !self.settings.theme_dark, color: pal.sub })
                .width(Length::Fixed(18.0))
                .height(Length::Fixed(18.0)),
        )
        .on_press(Message::ToggleTheme)
        .style(ghost_btn(pal))
        .padding([4, 10]);
        container(
            row![
                text("◎").size(19).color(pal.accent),
                text("PacketScope").size(15.5).font(bold()),
                text("│").color(pal.border),
                text(concat!("v", env!("CARGO_PKG_VERSION"))).size(13).color(pal.sub),
                iced::widget::horizontal_space(),
                pill,
                theme_btn,
            ]
            .spacing(10)
            .align_y(iced::Alignment::Center),
        )
        .padding([10, 16])
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(pal.panel.into()),
            border: Border { color: pal.border, width: 0.0, radius: 0.0.into() },
            ..Default::default()
        })
        .into()
    }

    fn panes(&self, pal: Pal) -> Element<'_, Message> {
        let base = row![
            self.left_pane(pal),
            self.middle_pane(pal),
            self.right_pane(pal),
        ]
        .width(Length::Fill)
        .height(Length::Fill);
        if !self.app_menu_open {
            return base.into();
        }
        // Popup menu under the middle pane's "more" button. A transparent
        // full-area catcher closes it on any outside click; the card is
        // positioned over the middle pane's top-right corner.
        let agg = self
            .selected_app
            .as_ref()
            .and_then(|k| self.aggregates().into_iter().find(|a| &a.key == k));
        let has_path = agg.map(|a| !a.path.is_empty()).unwrap_or(false);
        let item: Element<'_, Message> = if has_path {
            button(text("ファイルの場所を開く").size(12.5).color(pal.text))
                .on_press(Message::OpenFileLocation)
                .style(row_btn(pal, false))
                .padding([8, 12])
                .width(Length::Fill)
                .into()
        } else {
            container(text("ファイルの場所を開く").size(12.5).color(pal.faint))
                .padding([8, 12])
                .width(Length::Fill)
                .into()
        };
        let card = container(item)
            .width(Length::Fixed(216.0))
            .padding(5)
            .style(move |_| container::Style {
                background: Some(pal.panel.into()),
                border: Border { color: pal.border, width: 1.0, radius: 10.0.into() },
                shadow: iced::Shadow {
                    color: Color::from_rgba(0.0, 0.0, 0.0, 0.22),
                    offset: iced::Vector::new(0.0, 6.0),
                    blur_radius: 18.0,
                },
                ..Default::default()
            });
        let overlay = row![
            container(text("")).width(320),
            container(row![iced::widget::horizontal_space(), card])
                .width(430)
                .padding(iced::Padding { top: 62.0, right: 12.0, bottom: 0.0, left: 0.0 }),
            iced::widget::horizontal_space(),
        ];
        let catcher = mouse_area(
            container(text("")).width(Length::Fill).height(Length::Fill),
        )
        .on_press(Message::CloseAppMenu);
        stack![base, catcher, overlay]
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }

    fn icon_widget(&self, agg: &AppAgg, size: f32, pal: Pal) -> Element<'_, Message> {
        if let Some(Some(handle)) = self.icons.get(&agg.path) {
            return Image::new(handle.clone())
                .width(size)
                .height(size)
                .content_fit(iced::ContentFit::Contain)
                .into();
        }
        // Letter tile fallback (also used while the icon loads).
        let hue = agg.name.bytes().fold(0u32, |a, b| a.wrapping_add(b as u32) * 31);
        let bg = TILE_COLORS[(hue % TILE_COLORS.len() as u32) as usize];
        let letter = agg.name.chars().next().unwrap_or('?').to_uppercase().to_string();
        container(text(letter).size(size * 0.52).color(Color::WHITE).font(bold()))
            .width(size)
            .height(size)
            .center_x(size)
            .center_y(size)
            .style(move |_| container::Style {
                background: Some(bg.into()),
                border: Border { radius: (size * 0.24).into(), ..Default::default() },
                ..Default::default()
            })
            .into()
    }

    fn left_pane(&self, pal: Pal) -> Element<'_, Message> {
        let aggs = self.aggregates();
        let total: u64 = aggs.iter().map(|a| a.total).sum();
        let search = self.search.to_lowercase();
        let shown: Vec<&AppAgg> = aggs
            .iter()
            .filter(|a| {
                search.is_empty()
                    || a.name.to_lowercase().contains(&search)
                    || a.path.to_lowercase().contains(&search)
            })
            .collect();
        let mut list = Column::new().spacing(2).padding(iced::Padding { top: 2.0, right: 18.0, bottom: 2.0, left: 8.0 });
        for agg in &shown {
            let selected = self.selected_app.as_deref() == Some(agg.key.as_str());
            let content = row![
                self.icon_widget(agg, 30.0, pal),
                column![
                    text(ellipsize_mid(&agg.name, 27))
                        .size(13.5)
                        .font(semibold())
                        .wrapping(iced::widget::text::Wrapping::None)
                        .color(if selected { pal.accent } else { pal.text }),
                    text(short_path(&agg.path))
                        .size(10.0)
                        .wrapping(iced::widget::text::Wrapping::None)
                        .color(pal.faint),
                ]
                .spacing(1)
                .width(Length::Fill),
                text(fmt_size(agg.total))
                    .size(12.5)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .align_x(iced::alignment::Horizontal::Right)
                    .width(Length::Fixed(50.0))
                    .color(if selected { pal.accent } else { pal.sub }),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center);
            list = list.push(
                button(content)
                    .on_press(Message::SelectApp(agg.key.clone()))
                    .style(row_btn(pal, selected))
                    .padding([7, 9])
                    .width(Length::Fill),
            );
        }
        let body = column![
            row![
                text("APPLICATIONS").size(11).font(bold()).color(pal.faint),
                iced::widget::horizontal_space(),
                text(format!("{} apps · {}", aggs.len(), fmt_size(total))).size(11).color(pal.faint),
            ]
            .padding(iced::Padding { top: 12.0, right: 16.0, bottom: 6.0, left: 16.0 }),
            container(
                text_input("Search apps or executables", &self.search)
                    .on_input(Message::SearchChanged)
                    .size(12.5)
                    .padding([7, 10])
                    .style(input_style(pal)),
            )
            .padding(iced::Padding { top: 2.0, right: 12.0, bottom: 8.0, left: 12.0 }),
            scrollable(list).height(Length::Fill),
            row![
                text("●").size(8).color(pal.green),
                text(ellipsize(&self.status, 44)).size(11).color(pal.sub),
            ]
            .spacing(7)
            .padding([8, 16]),
        ];
        container(body)
            .width(320)
            .height(Length::Fill)
            .style(move |_| container::Style {
                background: Some(pal.panel.into()),
                ..Default::default()
            })
            .into()
    }

    fn middle_pane(&self, pal: Pal) -> Element<'_, Message> {
        let aggs = self.aggregates();
        let Some(sel_key) = self.selected_app.clone() else {
            return container(text("左の一覧からアプリを選んでください").color(pal.faint))
                .width(430)
                .height(Length::Fill)
                .center_x(Length::Fill)
                .center_y(Length::Fill)
                .style(move |_| pane_style(pal))
                .into();
        };
        let Some(agg) = aggs.iter().find(|a| a.key == sel_key) else {
            return container(text("")).width(430).height(Length::Fill).style(move |_| pane_style(pal)).into();
        };
        let flows = self.selected_flows();
        let mut list = Column::new().spacing(2).padding(iced::Padding { top: 2.0, right: 18.0, bottom: 2.0, left: 8.0 });
        for f in &flows {
            let selected = self.selected_flow.as_ref() == Some(&f.key);
            let up_dom = f.bytes_up >= f.bytes_down;
            let (arrow, acolor) = if up_dom { ("↗", pal.orange) } else { ("↙", pal.green) };
            // Displayed destination: for ECH flows the SNI is only
            // the cover name, so prefer the host recovered from
            // inside the decrypted stream (v1.3.1); while an ECH
            // flow is still encrypted, say so instead of presenting
            // the cover name as the destination.
            let host = match (&f.host_from_tls, &f.remote_host) {
                (Some(real), _) if !real.is_empty() => real.clone(),
                (Some(_), Some(cover)) => format!("{cover}（ECH の公開名）"),
                (Some(_), None) => "ECH（宛先は暗号化）".to_string(),
                (None, Some(h)) => h.clone(),
                (None, None) => f.key.proto.name(),
            };
            let mut ip_cell = row![text(f.key.remote_ip.to_string()).size(12.5)]
                .spacing(5)
                .align_y(iced::Alignment::Center);
            if f.tls_decrypted {
                ip_cell = ip_cell.push(
                    Canvas::new(LockIcon { color: pal.green }).width(13).height(13),
                );
            }
            let row_content = row![
                text(fmt_time(f.first_seen))
                    .size(11.5)
                    .font(iced::Font::MONOSPACE)
                    .color(if selected { pal.accent } else { pal.sub }),
                column![ip_cell, text(host).size(11).color(pal.faint),]
                    .spacing(0)
                    .width(Length::Fill),
                text(arrow).size(12).color(acolor),
                text(fmt_size(f.bytes_up + f.bytes_down))
                    .size(12)
                    .wrapping(iced::widget::text::Wrapping::None)
                    .color(pal.sub),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center);
            list = list.push(
                button(row_content)
                    .on_press(Message::SelectFlow(f.key.clone()))
                    .style(row_btn(pal, selected))
                    .padding([6, 9])
                    .width(Length::Fill),
            );
        }
        let seg = |label: &'static str, val: DirFilter| {
            let active = self.filter == val;
            button(text(label).size(12).color(if active { pal.text } else { pal.sub }))
                .on_press(Message::SetFilter(val))
                .style(seg_btn(pal, active))
                .padding([4, 12])
        };
        let body = column![
            row![
                self.icon_widget(agg, 40.0, pal),
                column![
                    text(agg.name.clone()).size(16.5).font(bold()),
                    text(if agg.path.is_empty() {
                        "パス不明".to_string()
                    } else if agg.path_estimate {
                        format!("{} （推定）", ellipsize(&agg.path, 46))
                    } else {
                        ellipsize(&agg.path, 52)
                    })
                    .size(11)
                    .color(pal.faint),
                ]
                .spacing(1)
                .width(Length::Fill),
                button(
                    Canvas::new(DotsIcon { color: pal.sub })
                        .width(Length::Fixed(16.0))
                        .height(Length::Fixed(16.0)),
                )
                .on_press(Message::ToggleAppMenu)
                .style(more_btn(pal, self.app_menu_open))
                .padding([5, 9]),
            ]
            .spacing(11)
            .align_y(iced::Alignment::Center)
            .padding(iced::Padding { top: 14.0, right: 16.0, bottom: 4.0, left: 16.0 }),
            row![
                stat_block(pal, &fmt_num(agg.packets), "PACKETS"),
                stat_block(pal, &fmt_size(agg.sent), "SENT"),
                stat_block(pal, &fmt_size(agg.received), "RECEIVED"),
            ]
            .padding(iced::Padding { top: 8.0, right: 16.0, bottom: 10.0, left: 16.0 }),
            row![
                container(row![seg("All", DirFilter::All), seg("Sent", DirFilter::Sent), seg("Received", DirFilter::Received)].spacing(2).padding(2))
                    .style(move |_| container::Style {
                        background: Some(pal.panel_alt.into()),
                        border: Border { radius: 8.0.into(), ..Default::default() },
                        ..Default::default()
                    }),
                iced::widget::horizontal_space(),
                text(format!("{} 件", flows.len())).size(11.5).color(pal.faint),
            ]
            .padding(iced::Padding { top: 0.0, right: 16.0, bottom: 8.0, left: 16.0 })
            .align_y(iced::Alignment::Center),
            row![
                text("TIME").size(10).font(bold()).color(pal.faint).width(64),
                text("REMOTE HOST · IP").size(10).font(bold()).color(pal.faint).width(Length::Fill),
                text("SIZE").size(10).font(bold()).color(pal.faint),
            ]
            .padding(iced::Padding { top: 2.0, right: 16.0, bottom: 4.0, left: 25.0 }),
            scrollable(list).height(Length::Fill),
            row![
                text(format!("{} of {} flows", flows.len(), agg.flow_count)).size(11).color(pal.faint),
                iced::widget::horizontal_space(),
                text(format!("{} packets", fmt_num(agg.packets))).size(11).color(pal.faint),
            ]
            .padding([8, 16]),
        ];
        container(body)
            .width(430)
            .height(Length::Fill)
            .style(move |_| pane_style(pal))
            .into()
    }

    fn right_pane(&self, pal: Pal) -> Element<'_, Message> {
        let Some(f) = self.current_flow() else {
            return container(
                text("履歴の行を選ぶと、送信・受信の内容が表示されます").color(pal.faint).size(13),
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .style(move |_| container::Style {
                background: Some(pal.bg.into()),
                ..Default::default()
            })
            .into();
        };
        let app_name = if f.process_name.is_empty() { "不明" } else { &f.process_name };
        let host = match (&f.host_from_tls, &f.remote_host) {
            (Some(real), _) if !real.is_empty() => real.clone(),
            (Some(_), Some(cover)) => format!("{cover}（ECH の公開名）"),
            (Some(_), None) => "ECH（宛先は暗号化）".to_string(),
            (None, Some(h)) => h.clone(),
            (None, None) => String::new(),
        };
        let up_dom = f.bytes_up >= f.bytes_down;
        let (pill_arrow, pill_word, pill_color) = if up_dom {
            ("↗", "SENT", pal.orange)
        } else {
            ("↙", "RECEIVED", pal.green)
        };
        // The pill must never be squeezed: with a long breadcrumb line the
        // row used to hand it whatever width was left, and its label wrapped
        // mid-word into a tall blob ("RECEIV/ED · 7.01/KB", v1.1.1 report).
        // No wrapping here, and the breadcrumb below is the Fill element, so
        // the pill is measured at its natural one-line width first and the
        // breadcrumb wraps inside the space that remains.
        let pill = container(
            text(format!("{} {} · {}", pill_arrow, pill_word, fmt_size(f.bytes_up + f.bytes_down)))
                .size(11)
                .font(bold())
                .color(pill_color)
                .wrapping(iced::widget::text::Wrapping::None),
        )
        .width(Length::Shrink)
        .padding([4, 10])
        .style(move |_| container::Style {
            background: Some(Color::from_rgba(pill_color.r, pill_color.g, pill_color.b, 0.14).into()),
            border: Border { radius: 999.0.into(), ..Default::default() },
            ..Default::default()
        });
        let (method_chip, title) = flow_title(f);
        let mut title_row = row![].spacing(10).align_y(iced::Alignment::Center);
        if let Some(m) = method_chip {
            title_row = title_row.push(
                container(text(m).size(11).font(bold()).color(Color::WHITE))
                    .padding([3, 8])
                    .style(move |_| container::Style {
                        background: Some(pal.accent.into()),
                        border: Border { radius: 5.0.into(), ..Default::default() },
                        ..Default::default()
                    }),
            );
        }
        title_row = title_row.push(
            text(title)
                .size(17)
                .font(semibold())
                .wrapping(iced::widget::text::Wrapping::WordOrGlyph),
        );
        let mut chips = row![chip(pal, f.key.proto.name())].spacing(6);
        if let Some(v) = &f.tls_version {
            chips = chips.push(chip(pal, v.clone()));
        }
        chips = chips.push(chip(pal, format!("{} packets", fmt_num(f.packets_up + f.packets_down))));
        let dur = f.last_seen.duration_since(f.first_seen).map(|d| d.as_secs()).unwrap_or(0);
        if dur > 0 {
            chips = chips.push(chip(pal, format!("{dur} s")));
        }
        let tab = |label: &'static str, val: DetailTab| {
            let active = self.detail_tab == val;
            button(text(label).size(12.5).color(if active { pal.accent } else { pal.sub }))
                .on_press(Message::SetDetailTab(val))
                .style(seg_btn(pal, active))
                .padding([5, 12])
        };
        let body: Element<'_, Message> = match self.detail_tab {
            DetailTab::Payload => self.payload_tab(pal, f),
            DetailTab::Headers => self.headers_tab(pal, f),
            DetailTab::Raw => self.raw_tab(pal, f),
        };
        let content = column![
            row![
                text(format!(
                    "{}  ›  {}  ·  {}  ·  {}",
                    app_name,
                    fmt_time(f.first_seen),
                    f.key.remote_ip,
                    host
                ))
                .size(11.5)
                .color(pal.faint)
                .width(Length::Fill),
                pill,
            ]
            .spacing(12)
            .align_y(iced::Alignment::Center),
            title_row,
            chips,
            row![
                tab("Payload", DetailTab::Payload),
                tab("Headers", DetailTab::Headers),
                tab("Raw bytes", DetailTab::Raw),
            ]
            .spacing(4),
            scrollable(
                container(body)
                    .width(Length::Fill)
                    .padding(iced::Padding { top: 0.0, right: 14.0, bottom: 0.0, left: 0.0 }),
            )
            .height(Length::Fill),
        ]
        .spacing(12)
        .padding([14, 18]);
        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(move |_| container::Style {
                background: Some(pal.bg.into()),
                ..Default::default()
            })
            .into()
    }

    fn payload_tab(&self, pal: Pal, f: &Flow) -> Element<'_, Message> {
        let dir_word = if f.bytes_up > 0 && f.bytes_down == 0 {
            "Sent to server"
        } else if f.bytes_down > 0 && f.bytes_up == 0 {
            "Received from server"
        } else {
            "Bidirectional"
        };
        let transport = match &f.tls_version {
            Some(v) => format!("{} · {}", f.key.proto.name(), v),
            None => f.key.proto.name(),
        };
        let pair = |label: &'static str, value: String| {
            column![
                text(label).size(9.5).font(bold()).color(pal.faint),
                text(value).size(12.5),
            ]
            .spacing(2)
            .width(Length::Fill)
        };
        let mut col = Column::new().spacing(16).width(Length::Fill);
        col = col.push(text("OVERVIEW").size(10.5).font(bold()).color(pal.faint));
        col = col.push(
            row![
                pair("DIRECTION", dir_word.to_string()),
                pair("TIMESTAMP", fmt_full(f.first_seen)),
            ]
            .spacing(16),
        );
        col = col.push(
            row![
                pair(
                    "PAYLOAD SIZE",
                    format!("{} · {} packets", fmt_size(f.bytes_up + f.bytes_down), fmt_num(f.packets_up + f.packets_down)),
                ),
                pair("TRANSPORT", transport),
            ]
            .spacing(16),
        );
        col = col.push(
            row![
                pair("CLIENT", format!("{}:{}", f.key.local_ip, f.key.local_port)),
                pair(
                    "SERVER",
                    match (&f.host_from_tls, &f.remote_host) {
                        (Some(real), _) if !real.is_empty() => format!(
                            "{}:{} · {}（復号から判明）",
                            f.key.remote_ip, f.key.remote_port, real
                        ),
                        (Some(_), Some(cover)) => format!(
                            "{}:{} · {}（ECH の公開名、本当の宛先は不明）",
                            f.key.remote_ip, f.key.remote_port, cover
                        ),
                        (Some(_), None) => format!(
                            "{}:{} · ECH（宛先は暗号化）",
                            f.key.remote_ip, f.key.remote_port
                        ),
                        (None, Some(h)) => {
                            format!("{}:{} · {}", f.key.remote_ip, f.key.remote_port, h)
                        }
                        (None, None) => format!("{}:{}", f.key.remote_ip, f.key.remote_port),
                    },
                ),
            ]
            .spacing(16),
        );
        if f.tls_decrypted {
            col = col.push(
                row![
                    Canvas::new(LockIcon { color: pal.green }).width(14).height(14),
                    text("TLS を鍵ログ（SSLKEYLOGFILE）で復号済み — Payload / Headers は復号後の内容、Raw bytes は暗号化されたままのバイト列です。")
                        .size(12)
                        .color(pal.green),
                ]
                .spacing(6)
                .align_y(iced::Alignment::Center),
            );
        }
        if f.bytes_up > 0 || !f.raw_up.is_empty() {
            col = col.push(self.body_section(pal, f, true));
        }
        if f.bytes_down > 0 || !f.raw_down.is_empty() {
            col = col.push(self.body_section(pal, f, false));
        }
        if f.bytes_up == 0 && f.bytes_down == 0 {
            col = col.push(text("このフローではまだパケットが観測されていません。").size(12.5).color(pal.sub));
        }
        col.into()
    }

    fn body_section(&self, pal: Pal, f: &Flow, up: bool) -> Element<'_, Message> {
        let content = if up { &f.content_up } else { &f.content_down };
        let raw = if up { &f.raw_up } else { &f.raw_down };
        let size = if up { f.bytes_up } else { f.bytes_down };
        let (label, arrow, acolor) = if up {
            ("SENT BODY", "↗", pal.orange)
        } else {
            ("RECEIVED BODY", "↙", pal.green)
        };
        let inner: Element<'_, Message> = match content {
            Content::Http { preview, .. } => {
                text(sanitize_text(preview)).size(12).font(iced::Font::MONOSPACE).into()
            }
            Content::Plain { preview } => {
                // Sanitized like every other preview path: a Plain
                // preview is still peer-controlled bytes (the HTTP/2
                // summary path used to reach the renderer raw).
                text(sanitize_text(preview)).size(12).font(iced::Font::MONOSPACE).into()
            }
            Content::Dns { names } => {
                text(sanitize_text(&format!("名前: {}", names.join(", ")))).size(12.5).into()
            }
            Content::TlsHello { server_name } => text(format!(
                "TLS ハンドシェイク（ClientHello）— 接続先ホスト名 (SNI): {}",
                server_name.clone().unwrap_or_else(|| "なし".into())
            ))
            .size(12.5)
            .into(),
            Content::Encrypted { kind } => column![
                text(format!("{kind} で暗号化されたペイロードです。中身は復号できないため、宛先・量・時刻のみ記録されています。"))
                    .size(12.5),
                text(if *kind == "TLS" {
                    "ブラウザ（Chrome / Brave / Firefox 系）の鍵ログ（SSLKEYLOGFILE）を用意すると、このフローを復号して表示できます。手順は README 参照。"
                } else {
                    ""
                })
                .size(12)
                .color(pal.sub),
                text(hex_preview(raw, 96)).size(11).font(iced::Font::MONOSPACE).color(pal.faint),
            ]
            .spacing(8)
            .into(),
            Content::Unknown => text(if f.sightings > 0 && f.packets_up + f.packets_down == 0 {
                "このフローは OS の接続表からの情報だけです。パケットを取得できていないため中身は分かりません。画面下部のキャプチャ状態を確認してください。"
            } else {
                "ペイロードはまだ取得できていません。通信が続くと表示されます。"
            })
            .size(12.5)
            .color(pal.sub)
            .into(),
        };
        column![
            row![
                text(label).size(10.5).font(bold()).color(pal.faint),
                text(arrow).size(11).color(acolor),
                iced::widget::horizontal_space(),
                text(fmt_size(size)).size(11).color(pal.faint),
            ]
            .spacing(6)
            .align_y(iced::Alignment::Center),
            container(inner)
                .padding(12)
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(pal.panel_alt.into()),
                    border: Border { radius: 10.0.into(), ..Default::default() },
                    ..Default::default()
                }),
        ]
        .spacing(7)
        .into()
    }

    fn headers_tab(&self, pal: Pal, f: &Flow) -> Element<'_, Message> {
        let mut col = Column::new().spacing(14).width(Length::Fill);
        for (label, raw, plain, client) in [
            ("SENT HEADERS ↗", &f.raw_up, &f.plain_up, true),
            ("RECEIVED HEADERS ↙", &f.raw_down, &f.plain_down, false),
        ] {
            let bytes = if plain.is_empty() { raw } else { plain };
            if bytes.is_empty() {
                continue;
            }
            // Decrypted HTTP/2 has no textual headers: show the
            // HPACK-decoded fields per stream instead of the raw
            // frame bytes (v1.3.0).
            let block = if f.tls_decrypted {
                netwatch::http2::headers_text(bytes, client)
                    .map(|t| sanitize_text(&t))
                    .unwrap_or_else(|| header_block(bytes))
            } else {
                header_block(bytes)
            };
            col = col.push(
                column![
                    text(label).size(10.5).font(bold()).color(pal.faint),
                    container(text(block).size(11.5).font(iced::Font::MONOSPACE))
                        .padding(12)
                        .width(Length::Fill)
                        .style(move |_| container::Style {
                            background: Some(pal.panel_alt.into()),
                            border: Border { radius: 10.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                ]
                .spacing(7),
            );
        }
        col = col.push(
            text("HTTP でないフローでは、ペイロード先頭のテキスト表示です。").size(11).color(pal.faint),
        );
        col.into()
    }

    fn raw_tab(&self, pal: Pal, f: &Flow) -> Element<'_, Message> {
        let mut col = Column::new().spacing(14).width(Length::Fill);
        for (label, raw) in [("SENT RAW ↗", &f.raw_up), ("RECEIVED RAW ↙", &f.raw_down)] {
            if raw.is_empty() {
                continue;
            }
            col = col.push(
                column![
                    text(label).size(10.5).font(bold()).color(pal.faint),
                    container(text(hex_dump(raw, 512)).size(10.5).font(iced::Font::MONOSPACE))
                        .padding(12)
                        .width(Length::Fill)
                        .style(move |_| container::Style {
                            background: Some(pal.panel_alt.into()),
                            border: Border { radius: 10.0.into(), ..Default::default() },
                            ..Default::default()
                        }),
                ]
                .spacing(7),
            );
        }
        col.into()
    }
}

/// Scrollbar clearance (v1.3.7): iced draws the vertical scrollbar
/// *over* the content, so rows that extend to a pane's edge — the
/// size column in the lists, the OVERVIEW values and payload boxes
/// in the detail pane — ended up half-hidden under it (field report,
/// v1.3.5). The fix pads the *content inside* each scrollable on the
/// right (list columns: right 18; detail body: wrapped with right
/// 14), leaving the bar itself at the pane's edge where it belongs.
/// v1.3.6 tried padding the pane containers instead, which moved the
/// bar inward too and left a dead strip at the edge — worse.

// ---------------------------------------------------------------- widgets

const TILE_COLORS: [Color; 8] = [
    Color::from_rgb(0.10, 0.45, 0.95),
    Color::from_rgb(0.55, 0.30, 0.90),
    Color::from_rgb(0.05, 0.65, 0.45),
    Color::from_rgb(0.90, 0.40, 0.20),
    Color::from_rgb(0.85, 0.60, 0.10),
    Color::from_rgb(0.20, 0.60, 0.85),
    Color::from_rgb(0.80, 0.30, 0.45),
    Color::from_rgb(0.35, 0.55, 0.30),
];

fn bold() -> iced::Font {
    iced::Font { weight: iced::font::Weight::Bold, ..iced::Font::with_name("Noto Sans JP") }
}
fn semibold() -> iced::Font {
    iced::Font { weight: iced::font::Weight::Semibold, ..iced::Font::with_name("Noto Sans JP") }
}

fn pane_style(pal: Pal) -> container::Style {
    container::Style { background: Some(pal.panel.into()), ..Default::default() }
}

fn stat_block(pal: Pal, value: &str, label: &str) -> Element<'static, Message> {
    column![
        text(value.to_string()).size(15).font(semibold()),
        text(label.to_string()).size(9.5).font(bold()).color(pal.faint),
    ]
    .spacing(1)
    .width(Length::Fill)
    .into()
}

fn chip(pal: Pal, label: String) -> Element<'static, Message> {
    container(text(label).size(11).color(pal.sub))
        .padding([3, 8])
        .style(move |_| container::Style {
            background: Some(pal.panel_alt.into()),
            border: Border { radius: 5.0.into(), ..Default::default() },
            ..Default::default()
        })
        .into()
}

fn row_btn(pal: Pal, selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, status| {
        let bg = if selected {
            Some(pal.sel_bg.into())
        } else {
            match status {
                button::Status::Hovered => Some(pal.panel_alt.into()),
                _ => None,
            }
        };
        button::Style {
            background: bg,
            text_color: pal.text,
            border: Border { radius: 8.0.into(), ..Default::default() },
            ..Default::default()
        }
    }
}

fn seg_btn(pal: Pal, active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, _| button::Style {
        background: if active { Some(pal.panel.into()) } else { None },
        text_color: pal.text,
        border: Border { radius: 6.0.into(), ..Default::default() },
        ..Default::default()
    }
}

fn more_btn(pal: Pal, open: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, status| button::Style {
        background: Some(if open || matches!(status, button::Status::Hovered) {
            pal.border.into()
        } else {
            pal.panel_alt.into()
        }),
        text_color: pal.sub,
        border: Border { radius: 7.0.into(), ..Default::default() },
        ..Default::default()
    }
}

fn ghost_btn(pal: Pal) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, status| button::Style {
        background: match status {
            button::Status::Hovered => Some(pal.panel_alt.into()),
            _ => None,
        },
        text_color: pal.sub,
        border: Border { radius: 7.0.into(), ..Default::default() },
        ..Default::default()
    }
}

fn input_style(pal: Pal) -> impl Fn(&Theme, text_input::Status) -> text_input::Style {
    move |_, _| text_input::Style {
        background: pal.panel_alt.into(),
        border: Border { radius: 8.0.into(), ..Default::default() },
        icon: pal.faint,
        placeholder: pal.faint,
        value: pal.text,
        selection: pal.accent,
    }
}

// ---------------------------------------------------------------- format

fn fmt_size(n: u64) -> String {
    const KB: f64 = 1024.0;
    let v = n as f64;
    let (x, unit) = if v >= KB * KB * KB * KB {
        (v / (KB * KB * KB * KB), "TB")
    } else if v >= KB * KB * KB {
        (v / (KB * KB * KB), "GB")
    } else if v >= KB * KB {
        (v / (KB * KB), "MB")
    } else if v >= KB {
        (v / KB, "KB")
    } else {
        return format!("{n} B");
    };
    if x >= 100.0 {
        format!("{x:.0} {unit}")
    } else if x >= 10.0 {
        format!("{x:.1} {unit}")
    } else {
        format!("{x:.2} {unit}")
    }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn jst_parts(t: SystemTime) -> (i64, u32, u32, u32, u32, u32) {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0) + 9 * 3600;
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400);
    // Civil date from days since epoch (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, (tod / 3600) as u32, ((tod / 60) % 60) as u32, (tod % 60) as u32)
}

fn fmt_time(t: SystemTime) -> String {
    let (_, _, _, h, mi, s) = jst_parts(t);
    format!("{h:02}:{mi:02}:{s:02}")
}

fn fmt_full(t: SystemTime) -> String {
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (y, m, d, h, mi, s) = jst_parts(t);
    format!("{} {}, {} · {:02}:{:02}:{:02} JST", MON[(m - 1) as usize], d, y, h, mi, s)
}

fn ellipsize(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}

/// Middle-ellipsis for the app-name line: keeps both ends readable.
fn ellipsize_mid(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head = max / 2;
    let tail = max - head - 1;
    let h: String = s.chars().take(head).collect();
    let t: String = s
        .chars()
        .rev()
        .take(tail)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{h}…{t}")
}

/// Path shortening for the app list, always in one form:
/// "C:\Windows\..\smartscreen.exe" — drive + first folder + ".." + the
/// executable name. Short paths are shown in full. No other truncation
/// shape is used, so the list reads consistently.
fn short_path(p: &str) -> String {
    if p.is_empty() {
        return "パス不明".to_string();
    }
    if p.chars().count() <= 34 {
        return p.to_string();
    }
    let sep = if p.contains('\\') { '\\' } else { '/' };
    let parts: Vec<&str> = p.split(sep).filter(|x| !x.is_empty()).collect();
    if parts.len() >= 3 {
        let root = if p.starts_with(sep) { sep.to_string() } else { String::new() };
        return format!(
            "{root}{}{sep}{}{sep}..{sep}{}",
            parts[0],
            parts[1],
            parts[parts.len() - 1]
        );
    }
    p.to_string()
}

/// Shape a peer-controlled headline for the detail title.
///
/// The request line comes straight from the wire (or from decrypted
/// bytes) and is not shaped for display: a WebSocket upgrade to
/// /hub?access_token=<JWT> produced a ~6 KB single-line title that
/// flooded the detail pane (field report v1.3.2). Two rules:
/// - the query string is *credentials by another name* (access
///   tokens, session ids, signed URLs), so the title shows the path
///   only; the full line stays available in the Payload/Headers
///   tabs, one click away, where the user chose to look.
/// - the result is sanitized and hard-capped, so no headline can
///   ever take over the layout again.
fn title_headline(headline: &str) -> String {
    const MAX: usize = 110;
    let clean = sanitize_text(headline);
    let mut s = clean.trim().to_string();
    if let Some(q) = s.find('?') {
        // Keep the " (Host: …)" trailer parse.rs appends, if present.
        let trailer = s[q..]
            .find("  (Host: ")
            .map(|i| s[q + i..].to_string())
            .unwrap_or_default();
        s = format!("{}?…{}", &s[..q], trailer);
    }
    if s.chars().count() > MAX {
        s = s.chars().take(MAX).collect::<String>() + "…";
    }
    s
}

fn flow_title(f: &Flow) -> (Option<String>, String) {
    for c in [&f.content_up, &f.content_down] {
        if let Content::Http { headline, .. } = c {
            let shaped = title_headline(headline);
            let mut it = shaped.splitn(2, ' ');
            let first = it.next().unwrap_or("");
            if ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].contains(&first) {
                let rest = it.next().unwrap_or("").to_string();
                return (Some(first.to_string()), rest);
            }
            return (None, shaped);
        }
    }
    let host = match (&f.host_from_tls, &f.remote_host) {
        (Some(real), _) if !real.is_empty() => real.clone(),
        (Some(_), Some(cover)) => format!("{cover}（ECH の公開名）"),
        (Some(_), None) => "ECH（宛先は暗号化）".to_string(),
        (None, Some(h)) => h.clone(),
        (None, None) => f.key.remote_ip.to_string(),
    };
    let label = match (&f.content_up, &f.content_down) {
        (Content::TlsHello { .. }, _) | (_, Content::TlsHello { .. }) => "TLS".to_string(),
        (Content::Encrypted { kind }, _) | (_, Content::Encrypted { kind }) => kind.to_string(),
        (Content::Dns { .. }, _) | (_, Content::Dns { .. }) => "DNS".to_string(),
        _ => f.key.proto.name(),
    };
    (None, format!("{label} · {host}"))
}

fn hex_preview(b: &[u8], max: usize) -> String {
    b.iter()
        .take(max)
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex_dump(b: &[u8], max: usize) -> String {
    let mut out = String::new();
    let n = b.len().min(max);
    for (off, chunk) in b[..n].chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|x| format!("{x:02x}")).collect();
        let asc: String = chunk
            .iter()
            .map(|&x| if (0x20..0x7f).contains(&x) { x as char } else { '·' })
            .collect();
        out.push_str(&format!("{:04x}  {:<47}  {}\n", off * 16, hex.join(" "), asc));
    }
    out
}

fn header_block(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let head = if let Some(pos) = text.find("\r\n\r\n") {
        &text[..pos]
    } else if let Some(pos) = text.find("\n\n") {
        &text[..pos]
    } else {
        &text
    };
    sanitize_text(&head.chars().take(1200).collect::<String>())
}

/// Make network-derived text safe to hand to the text renderer.
///
/// Packet payloads are arbitrary bytes. Decoded lossily, they can contain
/// Unicode bidi paragraph separators (U+001C..=U+001E, U+0085, U+2029) and
/// strong RTL characters; a line mixing the two makes cosmic-text — the
/// text shaping library under iced — panic on an assertion about bidi
/// paragraph direction, killing the whole app with no error shown
/// (reproduced with the v1.1.0 code path: Headers tab of a TLS flow).
/// Control and bidi-format characters therefore become '·' here (the same
/// convention as the payload preview), CR/CRLF become LF, and everything
/// else passes through unchanged.
fn sanitize_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            '\n' | '\t' => out.push(c),
            c if c.is_control() => out.push('·'),
            // Bidi controls / paragraph & line separators / BOM: harmless
            // in an editor, but they steer the shaper's paragraph logic.
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{feff}' => {
                out.push('·')
            }
            c if ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c) =>
            {
                out.push('·')
            }
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------- settings

/// Data directory for settings: %LOCALAPPDATA%\PacketScope on Windows.
fn data_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        base.join("PacketScope")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default();
        home.join("Library").join("Application Support").join("PacketScope")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| std::path::PathBuf::from(h).join(".config"))
                    .unwrap_or_default()
            });
        base.join("PacketScope")
    }
    #[cfg(not(any(windows, unix)))]
    {
        std::path::PathBuf::from("PacketScope")
    }
}

fn load_settings() -> Settings {
    let mut s = Settings {
        upload_burst_bytes_per_min: 10 * 1024 * 1024,
        alert_on_new_process: true,
        alert_on_new_destination: false,
        theme_dark: true,
        ..Default::default()
    };
    // Cap the read: settings.txt is a handful of short lines, and
    // this process runs elevated (audit 2026-11-08).
    let text = {
        use std::io::Read;
        let Ok(mut f) = std::fs::File::open(data_dir().join("settings.txt")) else {
            return s;
        };
        let mut buf = Vec::new();
        if f.by_ref().take(1024 * 1024).read_to_end(&mut buf).is_err() {
            return s;
        }
        String::from_utf8_lossy(&buf).into_owned()
    };
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k.trim() {
            "exclude" => {
                s.excluded.insert(v.trim().to_string());
            }
            "burst_mb" => {
                if let Ok(mb) = v.trim().parse::<u64>() {
                    // Saturating: a huge value in the file must not
                    // wrap the threshold to something tiny (audit
                    // 2026-11-08).
                    s.upload_burst_bytes_per_min = mb.saturating_mul(1024 * 1024);
                }
            }
            "new_process" => s.alert_on_new_process = v.trim() == "1",
            "new_dest" => s.alert_on_new_destination = v.trim() == "1",
            "theme" => s.theme_dark = v.trim() != "light",
            "keylog" => s.keylog_path = Some(v.trim().to_string()),
            _ => {}
        }
    }
    s
}

fn save_settings(s: &Settings) {
    let dir = data_dir();
    let _ = std::fs::create_dir_all(&dir);
    // Values land in a line-based file; a value containing a newline
    // (e.g. pasted into the exclude list) would otherwise inject
    // extra settings lines on the next load (audit 2026-11-08).
    let clean = |v: &str| v.replace(['\r', '\n'], " ");
    let mut out = String::new();
    for e in &s.excluded {
        out.push_str(&format!("exclude={}\n", clean(e)));
    }
    if let Some(p) = &s.keylog_path {
        out.push_str(&format!("keylog={}\n", clean(p)));
    }
    out.push_str(&format!(
        "burst_mb={}\nnew_process={}\nnew_dest={}\ntheme={}\n",
        s.upload_burst_bytes_per_min / (1024 * 1024),
        s.alert_on_new_process as u8,
        s.alert_on_new_destination as u8,
        if s.theme_dark { "dark" } else { "light" },
    ));
    let _ = std::fs::write(dir.join("settings.txt"), out);
}

// ------------------------------------------------------- file safety

/// True when `path` itself is a symlink or a Windows reparse point
/// (junction). Privileged code in this binary appends to log files in
/// user-writable directories and recursively deletes a small set of
/// folders; in both cases the *starting* path must not be a link
/// someone planted, because following it would redirect the write /
/// the deletion outside the intended tree (audit 2026-11-08).
fn is_reparse_point(path: &std::path::Path) -> bool {
    let Ok(md) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if md.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT covers junctions, which std's
        // is_symlink does not classify as symlinks.
        if md.file_attributes() & 0x0000_0400 != 0 {
            return true;
        }
    }
    false
}

/// If `path` is a symlink / reparse point, remove the link itself so
/// the caller goes on to create a fresh regular file at the path.
fn remove_if_reparse(path: &std::path::Path) {
    if is_reparse_point(path) {
        let _ = std::fs::remove_file(path);
    }
}

/// Recursively delete a directory tree, but never *through* a
/// reparse point at the root: if the root itself is a link, only the
/// link is removed. (Links below the root are already not followed
/// by remove_dir_all.)
fn remove_tree(path: &std::path::Path) -> std::io::Result<()> {
    if is_reparse_point(path) {
        return std::fs::remove_dir(path).or_else(|_| std::fs::remove_file(path));
    }
    std::fs::remove_dir_all(path)
}

/// Length + content digest of a file, for verifying that a copy we
/// are about to execute is still the file we copied.
fn file_digest(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::hash::Hasher;
    let bytes = std::fs::read(path).ok()?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    h.write(&bytes);
    Some((bytes.len() as u64, h.finish()))
}

// ---------------------------------------------------------------- uninstall

/// Remove the app, its shortcuts and its settings.
#[cfg(windows)]
fn uninstall_app() {
    use netwatch::system_setup::{confirm_box, info_box};
    use std::os::windows::process::CommandExt;
    if !confirm_box(
        "PacketScope をアンインストールしますか？\nプログラム本体と設定が削除されます。",
        "PacketScope のアンインストール",
    ) {
        return;
    }
    // The install folder is, by construction, where this
    // uninstall.exe lives; trust the executable's own location over
    // the ProgramFiles environment variable, which an unusual launch
    // environment could have altered (audit 2026-11-08). The env
    // derivation stays as a fallback for renamed copies.
    let env_dir = std::env::var("ProgramFiles")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("C:\\Program Files"))
        .join("PacketScope");
    let exe_dir = std::env::current_exe().ok().and_then(|exe| {
        let stem = exe
            .file_stem()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        exe.parent()
            .filter(|parent| {
                stem.starts_with("uninstall")
                    && parent
                        .file_name()
                        .map(|n| n.eq_ignore_ascii_case("PacketScope"))
                        .unwrap_or(false)
            })
            .map(|parent| parent.to_path_buf())
    });
    let install_dir = match exe_dir {
        Some(d) => {
            if d != env_dir {
                cleanup_log(&format!(
                    "uninstaller: install dir from exe location: {}",
                    d.to_string_lossy()
                ));
            }
            d
        }
        None => env_dir,
    };

    // Npcap is a shared driver (Wireshark and other capture tools use
    // it too), so removing it is strictly opt-in.
    let npcap_uninstaller = npcap_uninstaller_path();
    let remove_npcap = npcap_uninstaller.is_some()
        && confirm_box(
            "Npcap もアンインストールしますか？\n\nNpcap はパケット監視に使うドライバですが、Wireshark など他のアプリと共用のものです。PacketScope のためだけにインストールした場合は、削除しても問題ありません。",
            "Npcap のアンインストール",
        );

    // A running executable image is locked and cannot be deleted, so
    // stop the main app first if it is up. (This uninstaller runs
    // under the name uninstall.exe, so it never matches itself.)
    let _ = std::process::Command::new(netwatch::system_setup::system32_tool("taskkill.exe"))
        .args(["/IM", "packetscope.exe", "/F"])
        .creation_flags(0x0800_0000)
        .status();

    // Remove shortcuts.
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let sm = std::path::PathBuf::from(appdata)
            .join("Microsoft\\Windows\\Start Menu\\Programs\\PacketScope.lnk");
        let _ = std::fs::remove_file(sm);
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let desk = std::path::PathBuf::from(profile).join("Desktop\\PacketScope.lnk");
        let _ = std::fs::remove_file(desk);
    }
    let _ = std::process::Command::new(netwatch::system_setup::system32_tool("reg.exe"))
        .args([
            "delete",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PacketScope",
            "/f",
        ])
        .creation_flags(0x0800_0000)
        .status();
    let _ = remove_tree(&data_dir());
    // Remove Npcap (if the user opted in) BEFORE the completion
    // dialog: this waits for Npcap's uninstaller to actually finish,
    // so "完了しました" is only shown once it is really gone.
    if remove_npcap {
        if let Some(un) = &npcap_uninstaller {
            run_npcap_uninstaller(un);
        }
    }
    // Delete our own folder last, via a detached copy of this binary
    // running in cleanup-helper mode (see cleanup_helper).
    if install_dir.exists() {
        spawn_cleanup_helper(&install_dir);
        // Belt and suspenders: if a lock outlives the helper's
        // retries, Windows removes the files at the next reboot.
        for f in ["packetscope.exe", "uninstall.exe"] {
            let p = install_dir.join(f);
            if p.exists() {
                delete_on_reboot(&p);
            }
        }
        delete_on_reboot(&install_dir);
    }
    info_box("アンインストールが完了しました。", "PacketScope");
}

/// Whether this process holds an elevated (administrator) token.
#[cfg(windows)]
fn is_elevated() -> bool {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

/// Outcome of trying to relaunch this binary elevated.
#[cfg(windows)]
enum Relaunch {
    /// The elevated instance was started.
    Started,
    /// The user declined the UAC prompt (ERROR_CANCELLED). A
    /// deliberate choice, not a failure — the caller exits silently.
    Cancelled,
    /// The relaunch itself failed for another reason.
    Failed,
}

/// Relaunch this binary elevated (ShellExecute "runas", which shows
/// the UAC prompt), forwarding the current arguments plus an
/// --elevated-retry marker so a failed elevation cannot loop.
#[cfg(windows)]
fn relaunch_elevated(args: &[String]) -> Relaunch {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_CANCELLED};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    let Ok(exe) = std::env::current_exe() else {
        return Relaunch::Failed;
    };
    let wide = |s: &str| OsStr::new(s).encode_wide().chain(Some(0)).collect::<Vec<u16>>();
    // Full Windows command-line quoting (the CommandLineToArgvW
    // rules): the old version only wrapped space-containing args in
    // quotes and left embedded quotes and trailing backslashes
    // unescaped, which could bend how the elevated instance parsed
    // its arguments (audit 2026-11-08).
    let quote = |a: &str| {
        if !a.is_empty()
            && !a.contains([' ', '\t', '"'])
        {
            return a.to_string();
        }
        let mut out = String::with_capacity(a.len() + 2);
        out.push('"');
        let mut backslashes = 0usize;
        for c in a.chars() {
            match c {
                '\\' => backslashes += 1,
                '"' => {
                    for _ in 0..(backslashes * 2 + 1) {
                        out.push('\\');
                    }
                    out.push('"');
                    backslashes = 0;
                }
                c => {
                    for _ in 0..backslashes {
                        out.push('\\');
                    }
                    backslashes = 0;
                    out.push(c);
                }
            }
        }
        for _ in 0..(backslashes * 2) {
            out.push('\\');
        }
        out.push('"');
        out
    };
    let mut forwarded: Vec<String> = args.iter().skip(1).map(|a| quote(a)).collect();
    forwarded.push("--elevated-retry".to_string());
    let params = forwarded.join(" ");
    let exe_s = exe.to_string_lossy();
    let rc = unsafe {
        ShellExecuteW(
            null_mut(),
            wide("runas").as_ptr(),
            wide(&exe_s).as_ptr(),
            wide(&params).as_ptr(),
            null_mut(),
            1, // SW_SHOWNORMAL
        )
    };
    if rc as isize > 32 {
        return Relaunch::Started;
    }
    // ShellExecute reports a declined UAC prompt as SE_ERR_ACCESSDENIED
    // with the last error set to ERROR_CANCELLED.
    if unsafe { GetLastError() } == ERROR_CANCELLED {
        return Relaunch::Cancelled;
    }
    Relaunch::Failed
}

/// Append one line to %TEMP%\packetscope-cleanup.log. Both the
/// uninstaller and the cleanup helper write here, so a failed folder
/// removal leaves a trace instead of failing silently.
#[cfg(windows)]
fn cleanup_log(msg: &str) {
    use std::io::Write;
    let path = std::env::var_os("TEMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_default()
        .join("packetscope-cleanup.log");
    remove_if_reparse(&path);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "[{}] {msg}", fmt_full(std::time::SystemTime::now()));
    }
}

/// Run Npcap's own uninstaller and return only once it is really
/// finished, so the completion dialog in `uninstall_app` comes last.
///
/// Npcap's uninstaller is NSIS-based and hands the real work to a
/// detached copy of itself (Au_.exe under a %TEMP%\~nsu* folder):
/// the process we spawn exits within a second — the field log shows
/// launch and exit in the same second despite the `_?=<install dir>`
/// parameter that is supposed to make NSIS run in place. Waiting on
/// the spawned process alone therefore declares completion while
/// the uninstall window is still up (seen in v1.2.5 and v1.2.7).
///
/// v1.2.8 instead gated on machine state (Npcap's registry key,
/// driver service, uninstaller file) — and in the field those
/// conditions never lined up: the log stops at "confirming removal"
/// and, because the cleanup helper and the completion dialog sit
/// behind this function, the whole uninstall stalled. That gating
/// design was a mistake. The state checks stay, but only as log
/// diagnostics.
///
/// What the user actually watches is the uninstaller's window, so
/// v1.2.9 waits on processes: snapshot the uninstaller-like
/// processes before spawning, then wait until the spawned process
/// has exited AND no new uninstaller-like process (the detached
/// copy included) is alive. A hard deadline and a state line in
/// the log every 10 s keep any future stall bounded and visible.
#[cfg(windows)]
fn run_npcap_uninstaller(uninstaller: &std::path::Path) {
    let Some(dir) = uninstaller.parent().map(|p| p.to_path_buf()) else {
        return;
    };
    let before: std::collections::HashSet<u32> = uninstaller_like_processes(&dir)
        .into_iter()
        .map(|(pid, _)| pid)
        .collect();
    let arg = format!("_?={}", dir.to_string_lossy());
    cleanup_log("uninstaller: launching Npcap uninstaller (synchronous)");
    let mut child = match std::process::Command::new(uninstaller).arg(&arg).spawn() {
        Ok(c) => c,
        Err(e) => {
            cleanup_log(&format!(
                "uninstaller: Npcap uninstaller spawn failed: {e}"
            ));
            return;
        }
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    let mut announced: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut last_state_log: Option<std::time::Instant> = None;
    loop {
        let child_running = matches!(child.try_wait(), Ok(None));
        let active: Vec<(u32, String)> = uninstaller_like_processes(&dir)
            .into_iter()
            .filter(|(pid, _)| !before.contains(pid))
            .collect();
        for (pid, path) in &active {
            if announced.insert(*pid) {
                cleanup_log(&format!(
                    "uninstaller: Npcap uninstaller process active: pid {pid} {path}"
                ));
            }
        }
        if !child_running && active.is_empty() {
            cleanup_log("uninstaller: Npcap uninstall finished (no uninstaller process left)");
            break;
        }
        if last_state_log.is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(10)) {
            last_state_log = Some(std::time::Instant::now());
            cleanup_log(&format!(
                "uninstaller: waiting for Npcap: child_running={child_running} active_processes={} registry_key_present={} service_present={} uninstaller_file_present={}",
                active.len(),
                npcap_registry_present(),
                npcap_service_present(),
                uninstaller.exists(),
            ));
        }
        if std::time::Instant::now() >= deadline {
            cleanup_log("uninstaller: Npcap wait timed out after 300s; continuing anyway");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    // The uninstaller does not reliably delete itself, so remove
    // the leftover exe afterwards; driver files that are pending a
    // reboot stay Npcap's own responsibility.
    let _ = std::fs::remove_file(uninstaller);
    let _ = std::fs::remove_dir(&dir);
}

/// Whether Npcap's registry key (which stores its install dir) is
/// still there. Diagnostic for the Npcap wait log only — v1.2.8
/// gated completion on this and stalled in the field.
#[cfg(windows)]
fn npcap_registry_present() -> bool {
    ["SOFTWARE\\Npcap", "SOFTWARE\\WOW6432Node\\Npcap"]
        .iter()
        .any(|k| netwatch::system_setup::read_registry_sz_local_machine(k, "").is_some())
}

/// Whether the `npcap` driver service is still registered.
/// Diagnostic for the Npcap wait log only; when the SCM cannot be
/// reached we answer "present" (unknown reads as still there).
#[cfg(windows)]
fn npcap_service_present() -> bool {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS,
    };
    let name: Vec<u16> = "npcap".encode_utf16().chain(Some(0)).collect();
    unsafe {
        let mgr = OpenSCManagerW(std::ptr::null_mut(), std::ptr::null_mut(), SC_MANAGER_CONNECT);
        if mgr.is_null() {
            return true;
        }
        let svc = OpenServiceW(mgr, name.as_ptr(), SERVICE_QUERY_STATUS);
        let present = !svc.is_null();
        if present {
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(mgr);
        present
    }
}

/// All currently running processes that look like an Npcap
/// uninstaller: anything running out of the Npcap install dir, or a
/// detached uninstaller copy under %TEMP% (NSIS runs its self-copy
/// as Au_.exe inside a ~nsu* folder). Returns (pid, image path).
/// Callers diff two snapshots to follow one uninstall run without
/// reacting to uninstallers that were already open beforehand.
#[cfg(windows)]
fn uninstaller_like_processes(npcap_dir: &std::path::Path) -> Vec<(u32, String)> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let dir_prefix = format!("{}\\", npcap_dir.to_string_lossy().to_lowercase());
    let temp_l = std::env::var("TEMP").unwrap_or_default().to_lowercase();
    let mut found = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        // Snapshot failure is INVALID_HANDLE_VALUE (-1), not null;
        // checking only for null let the calls below run on an
        // invalid handle (they fail harmlessly, but say what we mean).
        if snap.is_null() || snap == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return found;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                if pid != 0 && pid != std::process::id() {
                    let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                    if !h.is_null() {
                        let mut buf = vec![0u16; 1024];
                        let mut len = buf.len() as u32;
                        if QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0 {
                            let path =
                                String::from_utf16_lossy(&buf[..len as usize]).to_lowercase();
                            let file = path.rsplit('\\').next().unwrap_or("");
                            if path.starts_with(&dir_prefix)
                                || file == "au_.exe"
                                || path.contains("~nsu")
                                || (file.contains("uninstall")
                                    && !temp_l.is_empty()
                                    && path.starts_with(&temp_l))
                            {
                                found.push((pid, path));
                            }
                        }
                        CloseHandle(h);
                    }
                }
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    found
}

/// Locate Npcap's own uninstaller, if Npcap is installed.
#[cfg(windows)]
fn npcap_uninstaller_path() -> Option<std::path::PathBuf> {
    for key in ["SOFTWARE\\Npcap", "SOFTWARE\\WOW6432Node\\Npcap"] {
        if let Some(dir) = netwatch::system_setup::read_registry_sz_local_machine(key, "") {
            let un = std::path::PathBuf::from(dir).join("uninstall.exe");
            if un.exists() {
                return Some(un);
            }
        }
    }
    let home = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
    let un = std::path::PathBuf::from(home).join("Npcap").join("uninstall.exe");
    un.exists().then_some(un)
}

/// Register `path` for deletion at the next reboot
/// (MoveFileEx with a null destination). Requires admin, which the
/// app manifest already guarantees. Returns whether the registration
/// succeeded — from a non-elevated process it silently fails, which
/// is exactly what the log needs to show.
#[cfg(windows)]
fn delete_on_reboot(path: &std::path::Path) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
    let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
    unsafe { MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) != 0 }
}

/// Spawn a detached copy of this binary (placed in %TEMP%) in
/// cleanup-helper mode to remove the install folder once this
/// uninstaller process has exited.
///
/// This replaces two earlier shell-based attempts, neither of which
/// worked on the user's machine: v1.2.3 fired a single `rmdir` from a
/// detached cmd after a ~2 s wait (the completion dialog kept
/// uninstall.exe alive and locked, so the delete lost the race), and
/// v1.2.4's retrying batch script still left the executables behind
/// and produced repeatedly flashing console windows. The helper is
/// the same GUI-subsystem binary, so no console window can appear,
/// and it logs its attempts to %TEMP%\packetscope-cleanup.log.
#[cfg(windows)]
fn spawn_cleanup_helper(install_dir: &std::path::Path) {
    use std::os::windows::process::CommandExt;
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let Some(temp) = std::env::var_os("TEMP").map(std::path::PathBuf::from) else {
        return;
    };
    // Remove a leftover script from the v1.2.4 batch mechanism.
    let _ = std::fs::remove_file(temp.join("packetscope-cleanup.bat"));
    // Unique *and unguessable* name per run: a helper from an earlier
    // uninstall may still be alive (a running exe cannot be
    // overwritten, so the name must differ), and a name predictable
    // from the pid alone would let a same-user process pre-plant or
    // swap the file we are about to run elevated (audit 2026-11-08).
    let helper = temp.join(format!(
        "packetscope-uninstall-helper-{}-{}.exe",
        std::process::id(),
        netwatch::system_setup::random_tag()
    ));
    if let Err(e) = std::fs::copy(&exe, &helper) {
        cleanup_log(&format!("uninstaller: helper copy failed: {e}"));
        return;
    }
    // Verify the copy is still exactly our binary before running it
    // with an administrator token.
    let want = file_digest(&exe);
    if want.is_none() || file_digest(&helper) != want {
        cleanup_log("uninstaller: helper copy failed integrity check; not spawning it");
        let _ = std::fs::remove_file(&helper);
        return;
    }
    let pid = std::process::id().to_string();
    // Start the helper with %TEMP% as its working directory: a
    // process cannot remove its own current directory, and the
    // inherited one is often the install folder itself.
    match std::process::Command::new(&helper)
        .args(["--cleanup-helper", &install_dir.to_string_lossy(), &pid])
        .current_dir(&temp)
        .creation_flags(0x0800_0000 | 0x0000_0008)
        .spawn()
    {
        Ok(_) => cleanup_log("uninstaller: helper spawned"),
        Err(e) => cleanup_log(&format!("uninstaller: helper spawn failed: {e}")),
    }
}

/// The only folder the cleanup helper may ever delete: a folder
/// named PacketScope directly under a Program Files root. Anything
/// else in the target argument means the invocation did not come
/// from our uninstaller (audit 2026-11-08).
#[cfg(windows)]
fn valid_cleanup_target(dir: &std::path::Path) -> bool {
    let named = dir
        .file_name()
        .map(|n| n.eq_ignore_ascii_case("PacketScope"))
        .unwrap_or(false);
    if !named {
        return false;
    }
    let Some(parent) = dir.parent() else {
        return false;
    };
    let parent_s = parent
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_lowercase();
    let mut roots: Vec<String> = ["C:\\Program Files", "C:\\Program Files (x86)"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Ok(v) = std::env::var(var) {
            roots.push(v);
        }
    }
    roots.iter().any(|r| {
        parent_s == r.trim_end_matches(['\\', '/']).to_lowercase()
    })
}

/// Full path of a process's executable image, when queryable.
#[cfg(windows)]
fn process_image_path(pid: u32) -> Option<std::path::PathBuf> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 || len == 0 {
            return None;
        }
        buf.truncate(len as usize);
        Some(std::path::PathBuf::from(String::from_utf16_lossy(&buf)))
    }
}

/// Cleanup helper mode: `--cleanup-helper <install_dir> <parent_pid>`.
///
/// Waits for the uninstaller process to exit (its image locks the
/// folder while it lives), then retries removing the install folder
/// for up to ~2 minutes. Falls back to delete-on-reboot for whatever
/// is left, and registers its own %TEMP% copy for reboot deletion as
/// well. Every step is logged to %TEMP%\packetscope-cleanup.log.
#[cfg(windows)]
fn cleanup_helper(args: &[String]) {
    // A process cannot remove its own current directory, and the
    // inherited working directory may be the install folder itself
    // (e.g. when the uninstaller was launched from Explorer). Move to
    // %TEMP% first — v1.2.5 missed this, which could leave an empty
    // install folder behind even with all files deleted.
    if let Some(temp) = std::env::var_os("TEMP") {
        let _ = std::env::set_current_dir(std::path::PathBuf::from(temp));
    }
    let log = cleanup_log;
    let pos = args.iter().position(|a| a == "--cleanup-helper");
    let (dir_arg, pid_arg) = match pos {
        Some(i) => (args.get(i + 1), args.get(i + 2)),
        None => (None, None),
    };
    let Some(dir_arg) = dir_arg else {
        return;
    };
    let dir = std::path::PathBuf::from(dir_arg);
    log(&format!(
        "helper: start, target = {}",
        dir.to_string_lossy()
    ));
    // This mode deletes a folder tree with an administrator token,
    // and the self-elevation path forwards arguments verbatim — so
    // the helper must not take the caller's word for what may be
    // deleted (audit 2026-11-08). Before this check, anyone who
    // could get this binary launched with a crafted argument and a
    // UAC consent had an arbitrary-folder recursive delete.
    let Some(parent_pid) = pid_arg.and_then(|s| s.parse::<u32>().ok()) else {
        log("helper: missing/invalid parent pid argument; refusing");
        return;
    };
    if !valid_cleanup_target(&dir) {
        log("helper: target is not the PacketScope install folder; refusing");
        return;
    }
    // When the parent can be identified, it must be the uninstaller
    // running from inside the target folder (that is how the real
    // flow works). An already-exited parent cannot be checked; the
    // target check above still bounds what can be deleted then.
    match process_image_path(parent_pid) {
        Some(image) => {
            let in_place = image
                .parent()
                .map(|p| {
                    p.to_string_lossy().eq_ignore_ascii_case(&dir.to_string_lossy())
                })
                .unwrap_or(false);
            if !in_place {
                log(&format!(
                    "helper: parent image {} is not inside the target folder; refusing",
                    image.to_string_lossy()
                ));
                return;
            }
        }
        None => log("helper: parent image not queryable (already exited?); proceeding"),
    }
    // A v1.2.4 batch script may still be looping; removing the file
    // makes its cmd abort instead of continuing.
    if let Some(temp) = std::env::var_os("TEMP") {
        let _ = std::fs::remove_file(
            std::path::PathBuf::from(temp).join("packetscope-cleanup.bat"),
        );
    }
    // Wait (bounded, up to ~5 minutes) for the uninstaller to exit.
    // A single 60 s wait proved too short in the field: a completion
    // dialog left open longer than that made the helper start while
    // uninstall.exe was still locking the folder.
    {
        let pid = parent_pid;
        unsafe {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{
                OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
            };
            let h = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
            if !h.is_null() {
                let mut waited_ms = 0u32;
                loop {
                    let rc = WaitForSingleObject(h, 5_000);
                    if rc == 0 || waited_ms >= 300_000 {
                        log(&format!(
                            "helper: parent wait rc = {rc} after ~{waited_ms} ms"
                        ));
                        break;
                    }
                    waited_ms += 5_000;
                }
                CloseHandle(h);
            } else {
                log("helper: parent handle unavailable, proceeding");
            }
        }
    }
    // Record what is in the folder, so a later failure can be tied
    // to a specific file.
    if let Ok(entries) = std::fs::read_dir(&dir) {
        let names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        log(&format!("helper: folder contents: {}", names.join(", ")));
    }
    let mut removed = !dir.exists();
    for attempt in 1..=120 {
        if removed {
            break;
        }
        match remove_tree(&dir) {
            Ok(()) => {
                removed = !dir.exists();
                log(&format!("helper: removed on attempt {attempt}"));
            }
            Err(e) => {
                if attempt == 1 || attempt % 30 == 0 {
                    log(&format!("helper: attempt {attempt} failed: {e}"));
                }
            }
        }
        if !removed {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    if dir.exists() {
        log("helper: still present after retries, registering reboot deletion");
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                let ok = delete_on_reboot(&p);
                log(&format!(
                    "helper: reboot-delete {} -> {ok}",
                    p.to_string_lossy()
                ));
            }
        }
        let ok = delete_on_reboot(&dir);
        log(&format!("helper: reboot-delete folder -> {ok}"));
    }
    if let Ok(me) = std::env::current_exe() {
        delete_on_reboot(&me);
    }
    log(&format!("helper: done, removed = {removed}"));
}

#[cfg(not(windows))]
fn cleanup_helper(_args: &[String]) {}

#[cfg(not(windows))]
fn uninstall_app() {}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    fn forbidden(c: char) -> bool {
        if c == '\n' || c == '\t' {
            return false;
        }
        c.is_control()
            || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{feff}')
            || ('\u{202a}'..='\u{202e}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
    }

    /// Regression test for the v1.1.0 crash: the Headers tab fed a lossy
    /// decode of raw TLS bytes to the text renderer, and random payloads
    /// regularly contain bidi paragraph separators + RTL characters, which
    /// panicked cosmic-text. Whatever bytes a flow carries, the string the
    /// Headers tab builds must be free of the steering characters.
    #[test]
    fn header_block_output_is_shape_safe_for_random_payloads() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        };
        for _ in 0..2000 {
            // TLS-record-like: structured header, then random bytes (the
            // shape ClientHello / ServerHello payloads have).
            let mut raw = vec![0x16, 0x03, 0x03, 0x05, 0x00, 0x01];
            for _ in 0..2042 {
                raw.push(next());
            }
            let block = header_block(&raw);
            assert!(
                !block.chars().any(forbidden),
                "unsafe char survived sanitize: {block:?}"
            );
            assert!(block.chars().count() <= 1200);
        }
    }

    #[test]
    fn sanitize_keeps_normal_text_and_normalizes_crlf() {
        assert_eq!(
            sanitize_text("GET / HTTP/1.1\r\nHost: example.jp\r\n日本語 OK"),
            "GET / HTTP/1.1\nHost: example.jp\n日本語 OK"
        );
        assert_eq!(sanitize_text("a\u{1c}b\u{202e}c\u{85}d"), "a·b·c·d");
    }

    #[test]
    fn header_block_still_extracts_http_headers() {
        let raw = b"GET /x HTTP/1.1\r\nHost: a.jp\r\n\r\nbody-body";
        assert_eq!(header_block(raw), "GET /x HTTP/1.1\nHost: a.jp");
    }

    /// Regression test for the v1.3.2 field report: a decrypted
    /// WebSocket upgrade whose request line carried a ~6 KB access
    /// token flooded the detail title and broke the layout. The
    /// shaped title must drop the query (credentials), stay short,
    /// and be shape-safe.
    #[test]
    fn title_headline_drops_query_and_caps_length() {
        let token = "eyJ".to_string() + &"a".repeat(5000);
        let headline = format!("GET /hub?access_token={token} HTTP/1.1  (Host: example.com)");
        let shaped = title_headline(&headline);
        assert!(shaped.starts_with("GET /hub?…"), "got: {shaped}");
        assert!(shaped.contains("(Host: example.com)"));
        assert!(!shaped.contains("access_token="), "token leaked into title: {shaped}");
        assert!(shaped.chars().count() <= 111, "title too long: {}", shaped.chars().count());
        // Ordinary headlines pass through untouched.
        assert_eq!(
            title_headline("GET /index.html HTTP/1.1  (Host: a.jp)"),
            "GET /index.html HTTP/1.1  (Host: a.jp)"
        );
        // Sanitization is part of shaping.
        assert_eq!(title_headline("GET /a\u{202e}b HTTP/1.1"), "GET /a·b HTTP/1.1");
    }

    #[test]
    fn http1_host_extracts_request_host() {
        let req = b"GET /hub?x=1 HTTP/1.1\r\nhost: Notifications.Example.com\r\n\r\n";
        assert_eq!(
            netwatch::parse::http1_host(req).as_deref(),
            Some("Notifications.Example.com")
        );
        assert_eq!(netwatch::parse::http1_host(b"HTTP/1.1 200 OK\r\n\r\n"), None);
        assert_eq!(netwatch::parse::http1_host(b"GET / HTTP/1.1\r\n\r\n"), None);
    }
}
