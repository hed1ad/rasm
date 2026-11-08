# `dasm analyze --json` — схема, версия 1

Контракт между CLI (Backend #3) и тестами (QA). Решение и правила версионирования — [ADR 0004](../adr/0004-analyze-json-format.md). Источник правды — типы `dasm_core::report::*` (`crates/dasm-core/src/report.rs`); этот документ их описывает.

```
dasm analyze <bin> [--json] [--insns] [--project file.dasm]
```

- `--json` — печатать отчёт в stdout (UTF-8, одна JSON-структура, завершающий `\n`).
- `--insns` — добавить `functions[].instructions`.
- `--project` — открыть/создать проект; пользовательские имена из журнала попадают в `functions[].name`.
- Коды возврата: `0` успех, `1` ошибка загрузки/анализа (текст в stderr, stdout пуст), `2` неверные аргументы.

## Общие правила

| Что | Как |
|---|---|
| Адрес | строка `"0x"` + hex нижнего регистра без ведущих нулей: `"0x401000"` |
| Размеры, смещения в файле, счётчики | JSON-число (целое ≥ 0) |
| Байты, SHA-256, build-id | hex нижнего регистра без разделителей: `"4889e5"` |
| Enum | строка `snake_case` |
| Нет значения | `null` (ключ присутствует) |
| Диапазон | `start` включительно, `end` исключительно |
| Порядок | сегменты, функции, блоки, инструкции, строки — по адресу; символы — по (адрес, имя); xrefs — по (from, to, kind), без дублей |
| Неизвестные поля | клиенты обязаны игнорировать (новые поля добавляются без смены `schema_version`) |

## Верхний уровень

| Поле | Тип | Описание |
|---|---|---|
| `schema_version` | int | `1` |
| `tool` | `{name: "dasm", version}` | версия `dasm-core` |
| `binary` | Binary | сводка |
| `segments` | Segment[] | |
| `sections` | Section[] | в порядке заголовков |
| `symbols` | Symbol[] | все источники (static, dynamic, dwarf, plt) |
| `imports` | Import[] | |
| `functions` | Function[] | |
| `xrefs` | Xref[] | |
| `strings` | String[] | |
| `stats` | Stats | |

### Binary

| Поле | Тип | Значения |
|---|---|---|
| `path` | string | как передан в CLI |
| `sha256` | hex | SHA-256 файла |
| `format` | enum | `elf`, `raw` |
| `kind` | enum | `executable`, `pie_executable`, `shared_library`, `relocatable`, `core`, `other` |
| `arch` | enum | `x86_64`, `x86`, `aarch64`, `arm`, `riscv64`, `mips`, `mock`, либо `{"unknown": <e_machine>}` |
| `endian` | enum | `little`, `big` |
| `bits` | int | 32 / 64 |
| `entry` | addr \| null | с учётом базы; `null`, когда в файле `e_entry == 0` (типично для `.so`) |
| `base` | addr | смещение загрузки (load bias), прибавленное к `p_vaddr`: для `ET_EXEC` всегда `0x0`; для PIE — `--base`, по умолчанию `0x0` (адреса как в readelf/objdump). Не путать с минимальным адресом сегмента |
| `build_id` | hex \| null | GNU build-id |
| `interpreter` | string \| null | `PT_INTERP` |
| `needed` | string[] | `DT_NEEDED` по порядку |

### Segment / Section

| Поле | Тип | Примечание |
|---|---|---|
| `name` | string | сегменты: `LOAD[0]`, `GNU_STACK`... |
| `start`, `end` | addr | |
| `file_offset` | int (у секции может быть `null` для NOBITS) | |
| `file_size` | int | |
| `kind` (Segment) | enum | тип program header: `load`, `dynamic`, `interp`, `note`, `phdr`, `tls`, `gnu_eh_frame`, `gnu_stack`, `gnu_relro`, `gnu_property`, либо `{"other": <p_type>}`. В `segments` попадают **все** program headers, не только `load` |
| `kind` (Section) | enum | `code`, `data`, `read_only_data`, `bss`, `metadata`, `other` |
| `tls` | bool (только Section) | `SHF_TLS` (`.tdata`, `.tbss`); диапазон TLS-`bss` перекрывает следующие секции |
| `perms` | string | `"r-x"`, `"rw-"`, `"r--"` |

### Symbol

`name`, `demangled` (string\|null), `address`, `size` (int\|null), `kind` (`function`, `ifunc`, `object`, `tls`, `section`, `file`, `unknown`), `binding` (`local`, `global`, `weak`), `source` (`analysis`, `plt`, `dynamic`, `static`, `dwarf`), `undefined` (bool: `SHN_UNDEF`; такой символ не именует адрес, `address` = `0x0`). Для `kind = tls` `address` — смещение в TLS-блоке, а не адрес.

### Import

`name`, `version` (`"GLIBC_2.2.5"`\|null), `library` (\|null), `kind`, `plt` (addr\|null), `got` (addr\|null).

### Function

| Поле | Тип | Описание |
|---|---|---|
| `entry` | addr | |
| `name` | string | пользовательское имя > символ (demangled) > `name@plt` > `sub_<hex>` |
| `size` | int | сумма размеров блоков |
| `insn_count` | int | |
| `source` | object | `{"type": "hint", "hint": "entry\|symbol\|eh_frame\|dwarf\|init_array\|fini_array\|plt"}` или `{"type": "call_target" \| "tail_call_target" \| "prologue" \| "user" \| "user_code"}` (`user` — `create_function`, `user_code` — `define_code`) |
| `flags` | object | `noreturn`, `thunk`, `plt`, `library` (bool) |
| `blocks` | Block[] | |
| `instructions` | Insn[] | только с `--insns` (иначе ключа нет) |

Block: `start`, `end`, `insn_count`, `successors: [{kind, target}]`, где `kind` ∈ `fallthrough`, `jump`, `conditional_taken`, `conditional_not_taken`, `switch`, `tail_call`; `target` — addr или `null` (косвенный переход).

Insn: `address`, `bytes` (hex), `len`, `mnemonic`, `operands` (текст, Intel-синтаксис), `tokens` — операнды токенами `{text, kind, target?}`; `kind` ∈ `mnemonic`, `register`, `immediate`, `address`, `symbol`, `keyword`, `punctuation`, `whitespace`, `string`, `comment`; `target` присутствует у кликабельных токенов. Конкатенация `tokens[].text` == `operands`.

### Xref

`from`, `to`, `kind` ∈ `call`, `jump`, `read`, `write`, `read_write` (один операнд читается и пишется: `inc [x]` — одна ссылка, не две), `data_ptr`.

### String

`address`, `encoding` ∈ `ascii`, `utf8`, `utf16_le`, `utf16_be`, `utf32_le`, `utf32_be`; `byte_len` (с терминатором); `value`.

### Stats

`function_count`, `insn_count`, `xref_count`, `string_count`, `analysis_ms`, `analysis_state` ∈ `idle`, `running`, `done`, `cancelled`, `failed` (внутренняя ошибка анализа: результаты частичные, CLI возвращает код 1).

## Пример

Синтетическая программа из `dasm_core::testing` (`--insns`; массивы сокращены, полный вывод — тест `report_roundtrips_through_json`):

```json
{
  "schema_version": 1,
  "tool": { "name": "dasm", "version": "0.1.0" },
  "binary": {
    "path": "./synthetic",
    "sha256": "4363104e6dfb1237502be5c4e7204f79179e53bd634fd12e0eb1f75d371f6ae5",
    "format": "elf",
    "kind": "executable",
    "arch": "mock",
    "endian": "little",
    "bits": 64,
    "entry": "0x401000",
    "base": "0x0",
    "build_id": "d45a0001",
    "interpreter": "/lib64/ld-linux-x86-64.so.2",
    "needed": ["libc.so.6"]
  },
  "segments": [
    { "name": "LOAD[0]", "kind": "load", "start": "0x401000", "end": "0x401060", "file_offset": 4096, "file_size": 96, "perms": "r-x" }
  ],
  "sections": [
    { "name": ".text", "start": "0x401000", "end": "0x401060", "file_offset": 4096, "file_size": 96, "kind": "code", "tls": false, "perms": "r-x" },
    { "name": ".bss", "start": "0x404010", "end": "0x404020", "file_offset": null, "file_size": 0, "kind": "bss", "tls": false, "perms": "rw-" }
  ],
  "symbols": [
    { "name": "main", "demangled": null, "address": "0x401010", "size": 41, "kind": "function", "binding": "global", "source": "static", "undefined": false }
  ],
  "imports": [
    { "name": "puts", "version": "GLIBC_2.2.5", "library": "libc.so.6", "kind": "function", "plt": "0x401050", "got": "0x404000" }
  ],
  "functions": [
    {
      "entry": "0x401010",
      "name": "main",
      "size": 41,
      "insn_count": 11,
      "source": { "type": "hint", "hint": "symbol" },
      "flags": { "noreturn": false, "thunk": false, "plt": false, "library": false },
      "blocks": [
        {
          "start": "0x401010", "end": "0x401029", "insn_count": 6,
          "successors": [
            { "kind": "conditional_taken", "target": "0x40102e" },
            { "kind": "conditional_not_taken", "target": "0x401029" }
          ]
        },
        { "start": "0x401029", "end": "0x40102e", "insn_count": 1, "successors": [ { "kind": "fallthrough", "target": "0x40102e" } ] },
        { "start": "0x40102e", "end": "0x401039", "insn_count": 4, "successors": [] }
      ],
      "instructions": [
        { "address": "0x401010", "bytes": "55", "len": 1, "mnemonic": "push", "operands": "rbp",
          "tokens": [ { "text": "rbp", "kind": "register" } ] },
        { "address": "0x40101b", "bytes": "e830000000", "len": 5, "mnemonic": "call", "operands": "puts@plt",
          "tokens": [ { "text": "puts@plt", "kind": "symbol", "target": "0x401050" } ] }
      ]
    }
  ],
  "xrefs": [
    { "from": "0x401014", "to": "0x402000", "kind": "data_ptr" },
    { "from": "0x40101b", "to": "0x401050", "kind": "call" },
    { "from": "0x401020", "to": "0x404008", "kind": "read" }
  ],
  "strings": [
    { "address": "0x402000", "encoding": "ascii", "byte_len": 13, "value": "Hello, dasm!" },
    { "address": "0x402020", "encoding": "utf16_le", "byte_len": 8, "value": "Hi!" }
  ],
  "stats": {
    "function_count": 4,
    "insn_count": 17,
    "xref_count": 8,
    "string_count": 3,
    "analysis_ms": 3,
    "analysis_state": "done"
  }
}
```

## Как QA сверяет с objdump/readelf

- Функции из FDE: множество `functions[].entry` ⊇ 95 % стартов FDE (`readelf --debug-dump=frames`), с учётом `binary.base`.
- Инструкции: для каждой `functions[].instructions[]` пара (`address`, `bytes`) совпадает со строкой `objdump -d --no-show-raw-insn`/`-d` на том же адресе; `len == bytes.len()/2`.
- Секции/сегменты/символы: сравнение с `readelf -SlW`, `nm -D`/`nm` (имена, адреса, размеры).
