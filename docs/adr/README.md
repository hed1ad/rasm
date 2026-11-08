# Architecture Decision Records

Формат: `NNNN-название.md`, разделы Контекст / Решение / Альтернативы / Последствия. Новое решение — новый файл; изменение принятого решения — новый ADR со ссылкой «заменяет NNNN».

| № | Решение | Статус |
|---|---|---|
| [0001](0001-workspace-and-crate-boundaries.md) | Cargo workspace из 7 крейтов; листовые крейты зависят только от `dasm-core`; версии и линты — в корневом `Cargo.toml` | предложено |
| [0002](0002-data-model-snapshots-operations-journal.md) | `Program` (неизменяемо) + `UserState` + `AnalysisResults` → `Snapshot`; публикация через `arc-swap`, коллекции — `imbl`; `Operation` с хранимой обратной операцией; журнал — источник правды, анализ — кэш | предложено |
| [0003](0003-analysis-pass-graph.md) | Проходы — чистые функции `(Snapshot, scope) → AnalysisDelta`; DAG по `PassId`; инвалидация по `ChangeKind` и диапазону; rayon по функциям; приоритет фокуса; `CancelToken` | предложено |
| [0004](0004-analyze-json-format.md) | Контракт `dasm analyze --json` = типы `dasm_core::report`; адреса — hex-строки; `schema_version` | предложено |
| [0005](0005-rust-qt-bridge-and-ui-build.md) | cxx-qt 0.10 (проверено с Qt 6.12/rustc 1.99); главный цикл у C++; уведомления через `qt_thread().queue` с коалесингом; CMake сверху; ADS: системный пакет, иначе FetchContent `v5.1.1` | предложено |

## Решения заказчика (2026-11-07)

| # | Вопрос | Решение | Где отражено |
|---|---|---|---|
| 1 | Rebase PIE | База фиксируется при создании проекта, адреса журнала абсолютные; rebase — позже отдельной операцией | ADR 0002, `docs/api/backlog.md` |
| 2 | Бинарь в проекте | По умолчанию копия; опционально «только ссылка» (путь + SHA-256) | ADR 0002, `SourceContent`, задачи Backend #3 |
| 3 | Один или два бинаря | Два: `dasm` (CLI/headless, без Qt) и `dasm-gui`; запуск GUI из `dasm` — backlog | ADR 0001, ADR 0005 |
| 4 | Автор операций | По умолчанию `$USER`, переопределяется настройкой в профиле пользователя | ADR 0002, `resolve_author` |
| 5 | Минимальная версия Qt | 6.8; CI: Arch + Debian 13; Ubuntu 24.04 — Flatpak/AppImage | ADR 0005, `ci.yml` |

Дополнительно: `dasm-qt` исключён из `default-members` (ADR 0001).

Отложенное — `docs/api/backlog.md`.
