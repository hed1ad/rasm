# ADR 0001. Структура workspace и границы крейтов

Статус: предложено (этап 0) · 2026-11-07 · Architect

## Контекст

Ядро — Rust, UI — C++/Qt 6. Волна B идёт параллельно шестью ролями, у каждой своя зона (см. `CLAUDE.md`). Нужны границы, при которых роли не правят чужие файлы, а связка «загрузчик → декодер → анализ → хранилище → CLI/UI» собирается только через публичный API `dasm-core`. Дизайн требует, чтобы встроенные ELF-загрузчик и x86 были «плагинами на публичном API».

## Решение

Один cargo workspace (`resolver = "3"`, edition 2024, `rust-version = 1.88`, лицензия Apache-2.0), крейты в `crates/`:

| Крейт | Назначение | Зависит от (dasm) | Ключевые внешние | Владелец |
|---|---|---|---|---|
| `dasm-core` | Типы модели, трейты расширения, снимки, журнал, сессия, JSON-отчёт, моки (`feature = "mock"`) | — | `arc-swap`, `imbl`, `serde`, `thiserror`, `sha2`, `libc` (только `cfg(unix)`: флаги открытия файла-ссылки) | Architect |
| `dasm-elf` | `impl Loader` для ELF + DWARF/.eh_frame | core | собственный парсер ELF, `gimli` | Backend #1 |
| `dasm-x86` | `impl Arch` для x86-64 | core | `iced-x86` | Backend #2 |
| `dasm-analysis` | `impl AnalysisDriver` (планировщик) + проходы | core | `rayon`, `crossbeam-channel` | Backend #2 |
| `dasm-db` | `impl ProjectStore` на SQLite | core | `rusqlite` (bundled) | Backend #3 |
| `dasm-cli` | бинарь `dasm` (headless) | core, elf, x86, analysis, db | `clap`, `serde_json`, `anyhow` | Backend #3 |
| `dasm-qt` | Rust-половина моста cxx-qt (staticlib для CMake) | core, elf, x86, analysis, db (*целевые*; в каркасе этапа 0 — только core) | `cxx-qt`, `cxx-qt-lib` (добавляет Frontend) | Frontend |

Граф зависимостей (стрелка — «зависит от»):

```
dasm-elf ──┐
dasm-x86 ──┤
dasm-analysis ─┼──► dasm-core
dasm-db ───┘
dasm-cli ─► core, elf, x86, analysis, db
dasm-qt  ─► core, elf, x86, analysis, db     (+ C++ ui/ через CMake)
```

Правила:

1. **Листовые крейты не знают друг о друге.** `dasm-analysis` не зависит от `dasm-x86` (работает с `dyn Arch`), `dasm-db` не зависит от анализа. Только «сборщики» (`dasm-cli`, `dasm-qt`) знают конкретные реализации и регистрируют их в `dasm_core::Registry`. В dev-dependencies листовых крейтов — только `dasm-core` с `features = ["mock"]` (для интеграционных тестов с настоящим ELF — `tests/` в зоне QA).
2. **Ошибки внешних библиотек не протекают** в публичный API: gimli/rusqlite-ошибки оборачиваются в `dasm_core::{LoadError, Error::Store}` со строкой.
3. **Версии сторонних крейтов** — только в `[workspace.dependencies]` корневого `Cargo.toml`; члены пишут `foo = { workspace = true }`. Добавление новой зависимости — через Architect (и `deny.toml` у Security).
4. **Линты** общие (`[workspace.lints]`): `unsafe_code = "deny"` (мост в `dasm-qt` снимает его локально с `// SAFETY:`), `clippy::unwrap_used`/`panic = "deny"`, `indexing_slicing = "warn"`, `missing_docs = "warn"`. В тестах unwrap/panic/индексация разрешены (`clippy.toml`). CI запускает clippy с `-D warnings`, т.е. все `warn` фактически обязательны.
5. **Тулчейн**: без `rust-toolchain.toml` — используем системный stable (Arch: 1.99.1), MSRV зафиксирован как 1.88 (минимум для let-chains в edition 2024). Если понадобится nightly-фича — отдельный ADR.
6. **`default-members` без `dasm-qt`** (решение заказчика). `cargo build/test/clippy` *без* `--workspace` собирают все крейты, кроме моста, и не требуют Qt — так работают Backend, QA и Security. Полный прогон (`--workspace`, с Qt) — отдельная CI-джоба `full` и обязателен перед слиянием изменений, затрагивающих `dasm-core` или `dasm-qt`.
6a. **QA-крейт `tests/` — член корневого workspace, но не `default-members`** (запрос QA, 2026-11). Причины: один `Cargo.lock` (отдельный лок резолвит заново и дрейфует), версии и features через `workspace = true` (у `serde` уже разошлись features), общие lints и попадание в гейт `--workspace`. Вне `default-members`, потому что оракульные golden-тесты идут ~1 мин: обычный `cargo test` их не запускает, `cargo test --workspace` и `-p dasm-tests` — запускают. Строка `"tests"` в `members` добавляется в том же коммите, где из `tests/Cargo.toml` убран собственный `[workspace]` (до этого cargo не может загрузить член без манифеста, а вложенный `[workspace]` даёт ошибку двух корней).
6b. **Тестовый код и lints.** `clippy.toml` (`allow-unwrap-in-tests` и т.п.) снимает `unwrap_used`/`expect_used`/`panic`/`indexing_slicing` только внутри `#[test]`-функций и `#[cfg(test)]`-модулей. Вспомогательные функции интеграционных тестов (`crates/*/tests/*.rs`, `tests/**`, `benches/**`) под это не попадают. Норма: в корне каждого такого target'а (`tests/foo.rs`, `benches/bar.rs`, `tests/src/lib.rs`) первой строкой
    ```rust
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    ```
    В `src/` продуктовых крейтов такие `allow` запрещены.
7. **Два бинаря** (решение заказчика, отклонение от дизайн-документа, где headless — «тот же бинарь без UI»): `dasm` (крейт `dasm-cli`, CLI/headless, **без зависимости от Qt**) и `dasm-gui` (CMake-цель из `ui/` + `dasm-qt`). Причины: CLI собирается и запускается на серверах/CI без Qt и X/Wayland-библиотек; меньше размер и поверхность атаки при пакетной обработке недоверенных бинарей; независимые циклы сборки. Цена: два исполняемых файла в пакете. Позже `dasm` без аргументов сможет запускать `dasm-gui`, если он установлен (backlog).
8. Версии, проверенные на crates.io 2026-11-07: gimli 0.34.0, iced-x86 1.22.0, rayon 1.12.0, rusqlite 0.41.1, serde 1.0.229, thiserror 2.0.21, clap 4.6.7, arc-swap 1.9.3, imbl 7.0.2, cxx 1.0.205, cxx-qt 0.10.0. Все компилируются в workspace (`cargo check` зелёный).

### Поправка 2026-11 (решение заказчика): ELF без goblin

`dasm-elf` использует **собственный bounds-checked парсер ELF** (заголовки, program/section headers, таблицы символов, версии, релокации, notes) и `gimli` только для DWARF и `.eh_frame`. `goblin` удалён из `[workspace.dependencies]`.

Обоснование:
- **Контроль над недоверенным вводом.** Загрузчик — самая атакуемая часть: каждый индекс, смещение и размер проверяется нами, с явными лимитами (`Limits`: секции, символы, `max_string_bytes`, `max_debug_work`), без чужих аллокаций по полям файла.
- **Best-effort разбор битых файлов.** Реверсеру нужен частичный результат из повреждённого или намеренно испорченного ELF (малварь, обрезанные дампы): пропустить сломанную запись и продолжить, а не отказать целиком, как делает строгий парсер.
- **Нет сторонней зависимости в атакуемой части**: меньше кода для аудита и фаззинга, нет внешних регрессий парсера и смены его API.
- Цена: свой код надо фаззить и поддерживать (цели Security `elf_load` и др.).

Альтернатива на будущее: для плагинов форматов PE и Mach-O рассмотреть крейт `object` (чтение многих форматов, активно поддерживается) — отдельным ADR, когда дойдёт до этих загрузчиков.

## Альтернативы

- **Один крейт с модулями.** Проще сборка, но роли конфликтуют в одном `Cargo.toml`/`lib.rs`, нет принудительных границ, компиляция не параллелится. Отвергнуто.
- **`dasm-analysis` зависит от `dasm-x86`.** Удобнее Backend #2, но ломает «архитектура как плагин» и блокирует SLEIGH. Отвергнуто: проходы работают только через `Arch`.
- **Отдельный крейт `dasm-session`/`dasm-engine`** для склейки store+journal+анализа. Пока не нужен: `Session` — в `dasm-core` (небольшой, без внешних зависимостей), склейка конкретных реализаций — 20 строк в каждом сборщике. Вернёмся, если сборщиков станет больше двух (Python-модуль на этапе 3).
- **Python-модуль и плагины** (`dasm-py`, `dasm-plugin-api`) появятся на этапе 3 отдельными крейтами поверх `dasm-core`.

## Последствия

- Backend/Frontend/QA пишут код против трейтов `dasm-core` и mock-реализаций, не дожидаясь друг друга.
- Изменение публичного API `dasm-core` — через Architect + ADR; добавление вариантов в `#[non_exhaustive]` enum'ы не ломает потребителей.
- Сборка `dasm-qt` требует Qt ≥ 6.8 (qmake6) только для `--workspace`/UI; роли без UI Qt не ставят. CI: джоба `rust` (default-members, Arch + Debian 13) и `full` (`--workspace` + UI, с Qt).
