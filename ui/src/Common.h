#pragma once
// Shared helpers: bridge include, string conversion, colors.

#include <QColor>
#include <QString>
#include <QtGlobal>

#include "dasm-qt/src/bridge.cxxqt.h"

namespace dasm {

inline QString qstr(const rust::String &s) {
    return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size()));
}

inline QString hexAddr(quint64 a, int width) {
    return QStringLiteral("%1").arg(a, width, 16, QLatin1Char('0'));
}

// Token kind ids mirror `data::token_kind_id` in crates/dasm-qt.
enum TokenKindId {
    Mnemonic = 0,
    Register,
    Immediate,
    Address,
    Symbol,
    Keyword,
    Punctuation,
    Whitespace,
    String,
    Comment
};

struct Theme {
    QColor background{0x1e, 0x1f, 0x22};
    QColor altBackground{0x25, 0x26, 0x2a};
    QColor text{0xd4, 0xd4, 0xd4};
    QColor dim{0x7a, 0x7d, 0x85};
    QColor cursorRow{0x2f, 0x3a, 0x4d};
    QColor separator{0x3a, 0x3d, 0x44};
    QColor label{0xe5, 0xc0, 0x7b};
    QColor link{0x61, 0xaf, 0xef};

    QColor token(int kind) const {
        switch (kind) {
        case Mnemonic: return {0xc6, 0x78, 0xdd};
        case Register: return {0x56, 0xb6, 0xc2};
        case Immediate: return {0xd1, 0x9a, 0x66};
        case Address: return {0xd1, 0x9a, 0x66};
        case Symbol: return {0x61, 0xaf, 0xef};
        case Keyword: return {0xc6, 0x78, 0xdd};
        case String: return {0x98, 0xc3, 0x79};
        case Comment: return {0x5c, 0x63, 0x70};
        default: return text;
        }
    }
};

inline const Theme &theme() {
    static const Theme t;
    return t;
}

} // namespace dasm
