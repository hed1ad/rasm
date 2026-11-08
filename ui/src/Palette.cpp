#include "Palette.h"

#include <QKeyEvent>
#include <QLineEdit>
#include <QListWidget>
#include <QPainter>
#include <QStyledItemDelegate>
#include <QVBoxLayout>
#include <algorithm>

#include "Commands.h"
#include "ListPanel.h"

namespace dasm {

namespace {

constexpr int kHintRole = Qt::UserRole + 1;
constexpr int kKindRole = Qt::UserRole + 2;
constexpr int kMaxFunctions = 30;
constexpr int kMaxStrings = 15;

class ResultDelegate : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;
    void paint(QPainter *p, const QStyleOptionViewItem &opt, const QModelIndex &idx) const override {
        QStyleOptionViewItem o = opt;
        initStyleOption(&o, idx);
        const QString title = o.text;
        o.text.clear();
        o.widget->style()->drawControl(QStyle::CE_ItemViewItem, &o, p, o.widget);
        const QRect r = opt.rect.adjusted(8, 0, -8, 0);
        const QString hint = idx.data(kHintRole).toString();
        const QString kind = idx.data(kKindRole).toString();
        p->save();
        p->setPen(opt.palette.color(QPalette::PlaceholderText));
        p->drawText(r, Qt::AlignVCenter | Qt::AlignLeft, kind);
        p->setPen(opt.state & QStyle::State_Selected
                      ? opt.palette.color(QPalette::HighlightedText)
                      : opt.palette.color(QPalette::Text));
        p->drawText(r.adjusted(90, 0, 0, 0), Qt::AlignVCenter | Qt::AlignLeft, title);
        p->setPen(opt.palette.color(QPalette::PlaceholderText));
        p->drawText(r, Qt::AlignVCenter | Qt::AlignRight, hint);
        p->restore();
    }
    QSize sizeHint(const QStyleOptionViewItem &opt, const QModelIndex &) const override {
        return {0, opt.fontMetrics.height() + 8};
    }
};

} // namespace

bool Palette::parseAddress(const QString &q, quint64 *out) {
    QString t = q.trimmed();
    bool prefixed = false;
    if (t.startsWith(QLatin1String("0x"), Qt::CaseInsensitive)) {
        t = t.mid(2);
        prefixed = true;
    }
    if (t.isEmpty() || (!prefixed && t.size() < 4)) return false;
    bool ok = false;
    const quint64 v = t.toULongLong(&ok, 16);
    if (ok) *out = v;
    return ok;
}

int Palette::fuzzyScore(const QString &pattern, const QString &text) {
    if (pattern.isEmpty()) return 0;
    int score = 0;
    int ti = 0;
    int prev = -2;
    for (const QChar pc : pattern) {
        if (pc.isSpace()) continue;
        const QChar p = pc.toLower();
        bool found = false;
        for (; ti < text.size(); ++ti) {
            if (text[ti].toLower() != p) continue;
            score += 10;
            if (ti == prev + 1) score += 15; // consecutive
            if (ti == 0 || !text[ti - 1].isLetterOrNumber()) score += 12; // word start
            prev = ti;
            ++ti;
            found = true;
            break;
        }
        if (!found) return -1;
    }
    return score - text.size() / 8;
}

Palette::Palette(SessionObject *session, CommandRegistry *commands, FunctionsModel *functions,
                 StringsModel *strings, QWidget *parent)
    : QFrame(parent), s_(session), commands_(commands), functions_(functions), strings_(strings) {
    setFrameShape(QFrame::StyledPanel);
    setAutoFillBackground(true);
    edit_ = new QLineEdit(this);
    edit_->setPlaceholderText(tr("Type a command, function, string, address or \"open <path>\""));
    list_ = new QListWidget(this);
    list_->setFocusPolicy(Qt::NoFocus);
    list_->setItemDelegate(new ResultDelegate(list_));
    list_->setUniformItemSizes(true);
    auto *lay = new QVBoxLayout(this);
    lay->setContentsMargins(6, 6, 6, 6);
    lay->setSpacing(4);
    lay->addWidget(edit_);
    lay->addWidget(list_);
    edit_->installEventFilter(this);
    connect(edit_, &QLineEdit::textChanged, this, [this] { refresh(); });
    connect(list_, &QListWidget::itemClicked, this, [this] { activateCurrent(); });
    hide();
}

void Palette::reposition() {
    QWidget *p = parentWidget();
    if (!p) return;
    const int w = std::min(680, p->width() - 40);
    const int h = std::min(400, p->height() - 60);
    setGeometry((p->width() - w) / 2, 40, w, h);
}

void Palette::openWith(const QString &prefill) {
    reposition();
    edit_->setText(prefill);
    refresh();
    show();
    raise();
    edit_->setFocus();
    edit_->setCursorPosition(static_cast<int>(prefill.size()));
}

void Palette::setQuery(const QString &q) { edit_->setText(q); }

std::vector<Palette::Result> Palette::search(const QString &query) const {
    std::vector<Result> out;
    const QString q = query.trimmed();

    if (q.startsWith(QLatin1String("open "), Qt::CaseInsensitive)) {
        const QString path = q.mid(5).trimmed();
        if (!path.isEmpty()) {
            out.push_back({Kind::OpenFile, tr("Open %1").arg(path), {}, {}, 0, path});
        }
    }
    quint64 addr = 0;
    if (parseAddress(q, &addr)) {
        out.push_back({Kind::Address,
                       s_->isMapped(addr) ? tr("Go to address") : tr("Address is not mapped"),
                       QStringLiteral("0x%1").arg(addr, 0, 16), {}, addr, {}});
    }

    // Commands.
    std::vector<std::pair<int, const Command *>> cmds;
    for (const Command &c : commands_->all()) {
        if (!c.action->isEnabled() && !q.isEmpty()) continue;
        const int sc = q.isEmpty() ? 0 : std::max(fuzzyScore(q, c.title), fuzzyScore(q, c.id) - 5);
        if (sc >= 0) cmds.emplace_back(sc, &c);
    }
    std::stable_sort(cmds.begin(), cmds.end(),
                     [](const auto &a, const auto &b) { return a.first > b.first; });
    for (const auto &[sc, c] : cmds) {
        if (!c->action->isEnabled()) continue;
        out.push_back({Kind::Command, c->title, c->key.toString(QKeySequence::NativeText), c->id, 0, {}});
    }

    if (q.size() >= 2) {
        // Functions.
        const auto &fs = functions_->items();
        std::vector<std::pair<int, size_t>> hits;
        for (size_t i = 0; i < fs.size(); ++i) {
            const int sc = fuzzyScore(q, qstr(fs[i].name));
            if (sc >= 0) hits.emplace_back(sc, i);
        }
        const size_t n = std::min<size_t>(kMaxFunctions, hits.size());
        std::partial_sort(hits.begin(), hits.begin() + static_cast<std::ptrdiff_t>(n), hits.end(),
                          [](const auto &a, const auto &b) { return a.first > b.first; });
        for (size_t k = 0; k < n; ++k) {
            const FuncDto &f = fs[hits[k].second];
            out.push_back({Kind::Function, qstr(f.name),
                           QStringLiteral("0x%1").arg(f.entry, 0, 16), {}, f.entry, {}});
        }
    }
    if (q.size() >= 3) {
        // Strings (substring).
        const auto &ss = strings_->items();
        int found = 0;
        for (size_t i = 0; i < ss.size() && found < kMaxStrings; ++i) {
            const QString v = qstr(ss[i].value);
            if (v.contains(q, Qt::CaseInsensitive)) {
                out.push_back({Kind::String, v, QStringLiteral("0x%1").arg(ss[i].addr, 0, 16),
                               {}, ss[i].addr, {}});
                ++found;
            }
        }
    }
    return out;
}

void Palette::refresh() {
    results_ = search(edit_->text());
    list_->clear();
    for (const Result &r : results_) {
        auto *item = new QListWidgetItem(r.title, list_);
        item->setData(kHintRole, r.hint);
        QString kind;
        switch (r.kind) {
        case Kind::Command: kind = tr("Command"); break;
        case Kind::Function: kind = tr("Function"); break;
        case Kind::String: kind = tr("String"); break;
        case Kind::Address: kind = tr("Address"); break;
        case Kind::OpenFile: kind = tr("File"); break;
        }
        item->setData(kKindRole, kind);
    }
    if (list_->count() > 0) list_->setCurrentRow(0);
}

int Palette::resultCount() const { return static_cast<int>(results_.size()); }

void Palette::activateCurrent() {
    const int row = list_->currentRow();
    if (row < 0 || static_cast<size_t>(row) >= results_.size()) return;
    const Result r = results_[static_cast<size_t>(row)];
    hide();
    switch (r.kind) {
    case Kind::Command: commands_->run(r.commandId); break;
    case Kind::OpenFile: emit openFile(r.path); break;
    default: emit navigateTo(r.addr); break;
    }
}

bool Palette::eventFilter(QObject *obj, QEvent *ev) {
    if (obj == edit_) {
        if (ev->type() == QEvent::KeyPress) {
            auto *k = static_cast<QKeyEvent *>(ev);
            const int n = list_->count();
            switch (k->key()) {
            case Qt::Key_Escape: hide(); return true;
            case Qt::Key_Down:
                if (n) list_->setCurrentRow((list_->currentRow() + 1) % n);
                return true;
            case Qt::Key_Up:
                if (n) list_->setCurrentRow((list_->currentRow() + n - 1) % n);
                return true;
            case Qt::Key_PageDown:
                if (n) list_->setCurrentRow(std::min(n - 1, list_->currentRow() + 8));
                return true;
            case Qt::Key_PageUp:
                if (n) list_->setCurrentRow(std::max(0, list_->currentRow() - 8));
                return true;
            case Qt::Key_Return:
            case Qt::Key_Enter: activateCurrent(); return true;
            default: break;
            }
        } else if (ev->type() == QEvent::FocusOut && isVisible()) {
            hide();
        }
    }
    return QFrame::eventFilter(obj, ev);
}

} // namespace dasm
