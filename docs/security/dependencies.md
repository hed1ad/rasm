# Зависимости: лицензии и политика

Security · 2026-11-08 · по `Cargo.lock` main `e21a4d5` (`cargo metadata --all-features`).
Проверка: `cargo deny check` (cargo-deny 0.20.2) — **advisories ok, bans ok,
licenses ok, sources ok**; для `fuzz/` — `cargo deny --manifest-path fuzz/Cargo.toml check` — ok.

## Лицензии сторонних крейтов (корневой workspace)

| Лицензия (SPDX из Cargo.toml) | Крейтов | Примеры | Совместимость с Apache-2.0 |
|---|---|---|---|
| `MIT OR Apache-2.0` и варианты записи | 91 | serde, serde_json, gimli, sha2, rayon, clap, anyhow, libc | да |
| `MIT` | 11 | iced-x86, rusqlite, libsqlite3-sys, archery | да |
| `Apache-2.0` | 1 | borsh-derive | да |
| `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | 2 | rustix, linux-raw-sys | да |
| `Zlib`, `Zlib OR Apache-2.0 OR MIT` | 4 | foldhash, bytemuck, wide | да |
| `Unlicense OR MIT` | 1 | memchr | да |
| `(MIT OR Apache-2.0) AND Unicode-3.0` | 1 | unicode-ident | да (данные Unicode, атрибуция) |
| `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | 1 | r-efi (только UEFI-цель) | да, выбираем MIT/Apache |
| **`MPL-2.0+`** | 2 | **imbl, imbl-sized-chunks** | да, с условиями (ниже) |

Крейтов без лицензии или с `license-file` нет. Встроенный SQLite
(`libsqlite3-sys`, `bundled`) — public domain.

## Риски

1. **imbl (MPL-2.0) — основа модели данных (ADR 0002).** MPL — слабый
   copyleft на уровне файлов: распространять бинарь Apache-2.0 можно; файлы
   imbl остаются под MPL, их исходники должны быть доступны получателю (ссылка
   на crates.io/репозиторий в NOTICE/документации к релизу). **Любой патч
   imbl (вендоринг, форк) публикуется под MPL-2.0.** Отказ от imbl не нужен.
2. **Qt 6 (LGPL-3.0) и Qt ADS (LGPL-2.1)** — не Rust-зависимости, cargo-deny их
   не видит. Динамическая линковка (системные пакеты) допустима; для
   AppImage/Flatpak — поставлять разделяемые библиотеки Qt, давать
   возможность их заменить, приложить тексты LGPL. Статическая линковка Qt
   потребует отдельного решения (Team Lead/заказчик).
3. **cxx/cxx-qt** (MIT OR Apache-2.0) — появятся с Frontend, проверить
   `cargo deny` после слияния.
4. **libfuzzer-sys** — `(MIT OR Apache-2.0) AND NCSA`, только в `fuzz/`, в
   продукт не попадает.
5. Дубликатов версий в графе normal/build-зависимостей нет (`cargo tree -d`);
   в `deny.toml` запрещены дубликаты парсеров недоверенных данных
   (gimli, iced-x86, serde_json, rusqlite, libsqlite3-sys, cpp_demangle, rustc-demangle).
6. `unmaintained`: RustSec не содержит предупреждений по текущему графу;
   `im` (не поддерживается) сознательно заменён на `imbl` (ADR 0002).

7. `goblin` удалён (`6b0fbf4`). `cpp_demangle` и `rustc-demangle` объявлены
   в `[workspace.dependencies]`, но ни один крейт их не использует, поэтому их
   нет в `Cargo.lock` и `cargo deny` их пока не проверяет. Лицензии по
   crates.io: обе двойные MIT/Apache-2.0, совместимы.

## Политика для новых зависимостей

- Разрешённые лицензии — список `allow` в `deny.toml` (permissive + MPL-2.0).
  GPL/AGPL/LGPL-only/SSPL/BUSL/«Commons Clause» — запрещены (cargo-deny
  отвергнет как не входящие в `allow`).
- Только crates.io; git-зависимости и сторонние реестры — `deny`.
- Новый парсер недоверенных данных (демангл, PE/Mach-O, архивы) — вместе с
  fuzz-целью.
