# ADR 0005. Мост Rust↔Qt (cxx-qt) и сборка UI

Статус: предложено (этап 0) · 2026-11-07 · Architect

## Контекст

UI — C++ Qt 6 Widgets + Qt Advanced Docking System (ADS), ядро — Rust. Дизайн выбрал cxx/cxx-qt и «тонкий слой биндингов». Нужно решить: кто владеет главным циклом, как UI узнаёт о новом снимке, где живут Qt-модели, как собирать (CMake/cargo) и подключать ADS. Риск из дизайна: «Rust + Qt усложняет сборку» — поэтому проведена проверка осуществимости.

## Проверка осуществимости (spike, 2026-11-07)

Черновик собирался во временном каталоге вне репозитория (удалён); его исходники приведены в приложении к этому ADR. C++ `main()` с `QApplication` + `QMainWindow` + `ads::CDockManager` + док-виджет; Rust-staticlib с cxx-qt QObject `SnapshotHub` (`#[qproperty]`, `#[qsignal]`, `#[qinvokable]`, `impl cxx_qt::Threading`). Rust-поток трижды «публикует снимок» через `qt_thread().queue(...)`, C++ ловит сигнал `snapshotReady` в UI-потоке и обновляет `QLabel`.

| Компонент | Версия |
|---|---|
| Qt | 6.12.0 (Arch `qt6-base 6.12.0-3`) |
| rustc / cargo | 1.99.1 (Arch) |
| cxx-qt / cxx-qt-lib / cxx-qt-build | 0.10.0 (`cxx-qt-lib` с `default-features = false`) |
| cxx | 1.0.205 |
| cxx-qt-cmake (FetchContent) | тег `0.10.0`, тянет Corrosion `v0.5.2` |
| Qt ADS (FetchContent) | тег `v5.1.1`, `BUILD_STATIC=ON` |
| CMake / Ninja / GCC | 4.4.4 / системный / 16 |

Результат: **работает.** Конфигурация и сборка без ошибок (≈ 2 мин с холодного кэша на 12 ядрах), запуск с `QT_QPA_PLATFORM=offscreen` — все три уведомления из фонового Rust-потока пришли в UI-поток, код возврата 0. Отдельно `cargo build` того же крейта без CMake тоже проходит (qmake6 находится сам) — значит, `cargo test --workspace` будет работать на машине с `qt6-base`.

Грабли:
1. Тег ADS — `v5.1.1`, а не `5.1.1` (у старых релизов теги без `v`).
2. ADS 5.1.1 с Qt 6.12 даёт 2 предупреждения компиляции (deprecated `QApplication::setActiveWindow`, `[[nodiscard]] QFile::open`) — безвредно, но не включать `-Werror` для чужого кода.
3. Сгенерированный заголовок: `#include "<crate_name>/src/<file>.cxxqt.h"` (путь от корня крейта).
4. Имена методов/сигналов в C++ по умолчанию snake_case — для Qt-стиля ставить `#[cxx_name = "camelCase"]`.
5. CMake ищет Vulkan-заголовки через `Qt6Gui` и пишет «Could NOT find WrapVulkanHeaders» — безвредно.
6. В CMake цель ADS одинаково доступна как `ads::qtadvanceddocking-qt6` и для системного пакета, и для FetchContent (в ADS есть ALIAS) — используем только это имя.
7. Системный пакет Arch `qt-advanced-docking-system 5.1.1` существует (extra), но на машине не установлен, поэтому ветка `find_package` не проверена — проверит CI (ставит пакет).

## Решение

### Владение и потоки

- **Главный цикл — у C++**: `ui/main.cpp` создаёт `QApplication`, окно, `app.exec()`. Rust не запускает свой цикл событий.
- Rust-сторона (`crates/dasm-qt`, staticlib) экспортирует QObject'ы через `#[cxx_qt::bridge]`. Центральный — `SessionObject`: владеет `dasm_core::Session` (через `Arc`), открывает файл в фоновом потоке (UI сразу показывает окно), отдаёт команды (`rename`, `undo`, `redo`, `setFocus`...) — каждая превращается в `Operation` → `Session::apply`.
- Анализ идёт в пуле rayon (ADR 0003), UI-поток только читает `Arc<Snapshot>` (`hub.load()`, без блокировок).

### Уведомление UI о новом снимке

`dasm-qt` реализует `SnapshotListener`: хранит `CxxQtThread<SessionObject>` и `AtomicBool pending`. В `snapshot_published` (поток анализа): если `!pending.swap(true)`, ставит в очередь Qt замыкание, которое сбрасывает `pending`, берёт **последний** снимок и эмитит `snapshotChanged(generation)`. Так 1000 публикаций подряд превращаются в одно-два событий в UI. Проверено в spike (механизм `qt_thread().queue`).

Виды на C++ по сигналу перечитывают видимые данные из нового снимка; если `generation` не изменилась — ничего не делают.

### Где живут модели

- **Тонкий мост**: Rust-QObject'ы отдают простые данные (числа, `QString`, `QList`, «страницу» строк листинга от адреса), C++ реализует `QAbstractItemModel`/кастомные виджеты (листинг с виртуализированным скроллом рисуется в C++ сам). Причина: вся тонкость Qt-моделей (begin/endResetModel, роли, сортировка-прокси) остаётся в C++, где у Frontend весь API Qt; мост остаётся маленьким и стабильным.
- Наследование QAbstractListModel прямо из Rust (cxx-qt `#[base = ...]`, `#[cxx_override]`) допустимо для простых списков, если окажется удобнее, — на усмотрение Frontend.
- `unsafe` разрешён только в модуле моста (`#![allow(unsafe_code)]` на модуль) с комментариями `// SAFETY:`.

### Сборка

- **CMake — верхний уровень сборки UI**: `ui/CMakeLists.txt`, `find_package(Qt6 6.8 REQUIRED COMPONENTS Core Gui Widgets)`, cxx-qt-cmake через FetchContent (тег `0.10.0`, синхронно с версией крейта cxx-qt в workspace), `cxx_qt_import_crate(MANIFEST_PATH ${CMAKE_SOURCE_DIR}/../crates/dasm-qt/Cargo.toml CRATES dasm-qt QT_MODULES Qt::Core Qt::Gui)`, `target_link_libraries(dasm-gui PRIVATE dasm-qt Qt::Widgets ads::qtadvanceddocking-qt6)`.
- **ADS**: сначала `find_package(qtadvanceddocking-qt6 CONFIG QUIET)` (пакеты Arch/Debian/Fedora и CI), иначе FetchContent с фиксированным тегом `v5.1.1`, `GIT_SHALLOW`, `BUILD_STATIC=ON`, `BUILD_EXAMPLES=OFF`. Для Flatpak/AppImage — FetchContent-ветка (статическая линковка). Vendoring исходников в репозиторий — нет.
- **Минимальная версия Qt — 6.8** (решение заказчика; LTS): `find_package(Qt6 6.8 REQUIRED ...)`. Поддерживаемые платформы сборки и CI: Arch Linux и Debian 13 (Qt 6.8, контейнеры). Ubuntu 24.04 (Qt 6.4) и прочие дистрибутивы со старым Qt — через Flatpak/AppImage, в CI не входят. API Qt новее 6.8 без проверки версии не использовать.
- **Cargo**: `dasm-qt` — член workspace, но не входит в `default-members` (ADR 0001): `cargo test` без Qt собирает всё остальное, `cargo test --workspace` — всё, с Qt. CI-джоба `full` (Arch: `qt6-base`, `qt-advanced-docking-system`; Debian 13: `qt6-base-dev`, ADS через FetchContent, `QMAKE=/usr/lib/qt6/bin/qmake`).
- Бинари (решение заказчика, ADR 0001): `dasm` (CLI, `dasm-cli`, без Qt) и `dasm-gui` (CMake). Запуск GUI из `dasm` без аргументов — backlog.

## Альтернативы

- **Ручной C ABI** (`extern "C"` + cbindgen): полный контроль, но сотни строк `unsafe` и ручное управление временем жизни. Отвергнуто дизайном и этим ADR.
- **Чистый `cxx` без cxx-qt**: нет готовых QObject/сигналов и `qt_thread().queue`, пришлось бы писать moc-обвязку вручную.
- **Главный цикл в Rust** (Rust `main` вызывает `QApplication::exec` через cxx-qt-lib): возможно, но ADS и кастомные виджеты на C++ удобнее собирать CMake-проектом с C++ `main`.
- **Сборка верхнего уровня через cargo (`build.rs` собирает C++ и ADS)**: плохо дружит с ADS, moc для C++-виджетов и IDE (Qt Creator/CLion понимают CMake). Отвергнуто.
- **QML вместо Widgets**: дизайн выбрал Widgets + ADS (нативный вид, кастомные быстрые виды).

## Последствия

- Frontend стартует с каркаса из spike (CMakeLists + bridge), его можно перенести почти без изменений.
- Версия cxx-qt в `[workspace.dependencies]` и тег cxx-qt-cmake в `ui/CMakeLists.txt` обновляются **вместе**.
- Сборка UI с холодного кэша ≈ 2 мин; CI кэширует `~/.cargo` и каталог cargo внутри `build/`.
- Сборочная зависимость от сети (FetchContent) при отсутствии системного ADS; для офлайн-сборок — `FETCHCONTENT_SOURCE_DIR_ADS`/`FETCHCONTENT_SOURCE_DIR_CXXQT`.

## Приложение: файлы spike
Каталог черновика был временным, поэтому ключевые файлы приведены здесь (Frontend может взять их за основу `ui/` и `crates/dasm-qt`; в `ui/` минимальная версия — `Qt6 6.8`, а не 6.5 как в черновике).
Каталог черновика временный, поэтому ключевые файлы приведены здесь (Frontend может взять их за основу `ui/` и `crates/dasm-qt`).

`app/CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.24)
project(cxxqt_spike LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Gui Widgets)

include(FetchContent)
FetchContent_Declare(CxxQt
    GIT_REPOSITORY https://github.com/KDAB/cxx-qt-cmake.git
    GIT_TAG 0.10.0)
FetchContent_MakeAvailable(CxxQt)

# Qt Advanced Docking System: prefer system package, fall back to FetchContent.
find_package(qtadvanceddocking-qt6 CONFIG QUIET)
if(NOT qtadvanceddocking-qt6_FOUND)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(BUILD_STATIC ON CACHE BOOL "" FORCE)
    FetchContent_Declare(ads
        GIT_REPOSITORY https://github.com/githubuser0xFFFF/Qt-Advanced-Docking-System.git
        GIT_TAG v5.1.1
        GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(ads)
    set(ADS_TARGET qtadvanceddocking-qt6)
else()
    set(ADS_TARGET ads::qtadvanceddocking-qt6)
endif()

cxx_qt_import_crate(
    MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../bridge/Cargo.toml
    CRATES spike_bridge
    QT_MODULES Qt::Core)

add_executable(spike main.cpp)
target_link_libraries(spike PRIVATE spike_bridge Qt::Widgets ${ADS_TARGET})
```

`bridge/Cargo.toml`:

```toml
[package]
name = "spike_bridge"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["staticlib"]

[dependencies]
cxx = "1.0.205"
cxx-qt = "0.10.0"
cxx-qt-lib = { version = "0.10.0", default-features = false }

[build-dependencies]
cxx-qt-build = "0.10.0"
```

`bridge/build.rs`: `CxxQtBuilder::new().file("src/lib.rs").build();`

`bridge/src/lib.rs`:

```rust
//! Spike: a QObject owned by C++ that receives "snapshot ready" notifications
//! from a background Rust thread via CxxQtThread::queue.
#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    extern "RustQt" {
        #[qobject]
        #[qproperty(u64, generation)]
        #[qproperty(QString, status)]
        type SnapshotHub = super::SnapshotHubRust;

        #[qsignal]
        #[cxx_name = "snapshotReady"]
        fn snapshot_ready(self: Pin<&mut SnapshotHub>, generation: u64);

        #[qinvokable]
        #[cxx_name = "startAnalysis"]
        fn start_analysis(self: Pin<&mut SnapshotHub>);
    }

    impl cxx_qt::Threading for SnapshotHub {}
}

use core::pin::Pin;
use cxx_qt::Threading;
use cxx_qt_lib::QString;

#[derive(Default)]
pub struct SnapshotHubRust {
    generation: u64,
    status: QString,
}

impl qobject::SnapshotHub {
    fn start_analysis(self: Pin<&mut Self>) {
        let qt_thread = self.qt_thread();
        std::thread::spawn(move || {
            for g in 1..=3u64 {
                std::thread::sleep(std::time::Duration::from_millis(20));
                // Publishing a new snapshot would happen here (ArcSwap::store),
                // then the UI thread is poked through the Qt event loop.
                let _ = qt_thread.queue(move |mut hub| {
                    hub.as_mut().set_generation(g);
                    hub.as_mut()
                        .set_status(QString::from(&format!("snapshot #{g}")));
                    hub.as_mut().snapshot_ready(g);
                });
            }
        });
    }
}
```

`app/main.cpp`:

```cpp
#include <QApplication>
#include <QLabel>
#include <QMainWindow>
#include <QTimer>
#include <cstdio>
#include "DockManager.h"
#include "spike_bridge/src/lib.cxxqt.h"

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QMainWindow win;
    auto *dm = new ads::CDockManager(&win);
    auto *label = new QLabel("waiting");
    auto *dock = new ads::CDockWidget(dm, "Listing");
    dock->setWidget(label);
    dm->addDockWidget(ads::CenterDockWidgetArea, dock);

    SnapshotHub hub;
    int seen = 0;
    QObject::connect(&hub, &SnapshotHub::snapshotReady, &win, [&](quint64 g) {
        label->setText(hub.getStatus());
        std::printf("UI got snapshot %llu: %s\n", (unsigned long long)g,
                    hub.getStatus().toUtf8().constData());
        if (++seen == 3) app.quit();
    });
    hub.startAnalysis();
    QTimer::singleShot(5000, &app, [&] { std::puts("TIMEOUT"); app.exit(2); });
    win.show();
    return app.exec();
}
```
