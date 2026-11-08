#include "ListingView.h"

#include <QApplication>
#include <QFontDatabase>
#include <QFrame>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QVBoxLayout>
#include <algorithm>

namespace dasm {

namespace {
constexpr int kScale = 1'000'000; // scrollbar resolution
constexpr int kWheelRowsPerStep = 3;
constexpr int kLabelChars = 22;
constexpr int kBytesChars = 31;
constexpr int kMnemonicChars = 8;
} // namespace

ListingView::ListingView(SessionObject *session, QWidget *parent)
    : QAbstractScrollArea(parent), s_(session) {
    font_ = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    font_.setPointSizeF(std::max(10.0, font_.pointSizeF()));
    viewport()->setFont(font_);
    viewport()->setMouseTracking(true);
    viewport()->setBackgroundRole(QPalette::Base);
    setFocusPolicy(Qt::StrongFocus);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    setFrameShape(QFrame::NoFrame);

    focusTimer_.setSingleShot(true);
    focusTimer_.setInterval(120);
    connect(&focusTimer_, &QTimer::timeout, this, [this] {
        if (!hasCursor_ || !s_->isOpen()) return;
        quint64 end = top_;
        if (!rows_.empty()) {
            const RowDto &last = rows_[rows_.size() - 1];
            end = last.addr + last.len;
        }
        s_->setFocus(cursor_, top_, end);
    });

    connect(verticalScrollBar(), &QScrollBar::actionTriggered, this,
            [this](int a) { onScrollAction(a); });
    connect(verticalScrollBar(), &QScrollBar::sliderMoved, this, [this](int v) {
        if (total_ == 0) return;
        const long double frac =
            std::clamp(static_cast<long double>(v) / kScale, 0.0L, 1.0L);
        quint64 off = static_cast<quint64>(frac * static_cast<long double>(total_));
        if (off >= total_) off = total_ - 1;
        top_ = s_->offsetToAddress(off);
        rowsValid_ = false;
        viewport()->update();
        scheduleFocusReport();
    });

    editor_ = new QFrame(viewport());
    editor_->setFrameShape(QFrame::StyledPanel);
    editor_->setAutoFillBackground(true);
    auto *lay = new QVBoxLayout(editor_);
    lay->setContentsMargins(4, 4, 4, 4);
    lay->setSpacing(2);
    edit_ = new QLineEdit(editor_);
    edit_->setFont(font_);
    hint_ = new QLabel(editor_);
    hint_->setTextFormat(Qt::PlainText);
    hint_->setForegroundRole(QPalette::PlaceholderText);
    lay->addWidget(edit_);
    lay->addWidget(hint_);
    editor_->hide();
    edit_->installEventFilter(this);
    connect(edit_, &QLineEdit::returnPressed, this, [this] { endEdit(true); });
}

int ListingView::lineHeight() const { return QFontMetrics(font_).height() + 2; }

int ListingView::fullRows() const {
    return std::max(1, viewport()->height() / lineHeight());
}

int ListingView::visibleRowCount() const { return fullRows(); }

QString ListingView::rowMnemonic(int i) const {
    if (i < 0 || static_cast<size_t>(i) >= rows_.size()) return {};
    return qstr(rows_[static_cast<size_t>(i)].mnemonic);
}

quint64 ListingView::rowAddress(int i) const {
    if (i < 0 || static_cast<size_t>(i) >= rows_.size()) return 0;
    return rows_[static_cast<size_t>(i)].addr;
}

QList<QPair<QRect, quint64>> ListingView::linkHits() const {
    QList<QPair<QRect, quint64>> out;
    for (const Hit &h : hits_) out.append({h.rect, h.target});
    return out;
}

QString ListingView::rowLabel(int i) const {
    if (i < 0 || static_cast<size_t>(i) >= rows_.size()) return {};
    return qstr(rows_[static_cast<size_t>(i)].label);
}

bool ListingView::editing() const { return editor_->isVisible(); }

void ListingView::fetchRows(quint64 from, int count) {
    rows_ = s_->listingFrom(from, count);
    if (!rows_.empty()) top_ = rows_[0].addr; // align to an item boundary
    rowsTop_ = top_;
    rowsWanted_ = count;
    rowsValid_ = true;
}

void ListingView::ensureRows() {
    const int want = fullRows() + 2;
    if (rowsValid_ && rowsTop_ == top_ && rowsWanted_ >= want) return;
    fetchRows(top_, want);
}

int ListingView::rowIndexOf(quint64 addr) const {
    for (size_t i = 0; i < rows_.size(); ++i) {
        if (rows_[i].addr == addr) return static_cast<int>(i);
    }
    return -1;
}

void ListingView::reload() {
    const StatusDto st = s_->status();
    addrWidth_ = std::max<int>(8, st.addr_width);
    total_ = s_->mappedSize();
    rowsValid_ = false;
    hasCursor_ = false; // a new session: nothing of the old one carries over
    top_ = 0;
    quint64 start = st.has_entry ? st.entry : s_->offsetToAddress(0);
    goTo(start);
    if (!hasCursor_) goTo(s_->offsetToAddress(0)); // entry not mapped
    syncScrollbar();
}

void ListingView::invalidate() {
    total_ = s_->mappedSize();
    rowsValid_ = false;
    if (hasCursor_) {
        auto r = s_->listingFrom(cursor_, 1);
        if (!r.empty() && r[0].addr != cursor_) cursor_ = r[0].addr;
    }
    viewport()->update();
}

void ListingView::setCursor(quint64 addr) {
    cursor_ = addr;
    hasCursor_ = true;
    emit cursorMoved(addr);
    scheduleFocusReport();
    viewport()->update();
}

void ListingView::goTo(quint64 addr) {
    auto item = s_->listingFrom(addr, 1);
    if (item.empty()) return;
    const quint64 target = item[0].addr;
    ensureRows();
    const int idx = rowIndexOf(target);
    if (idx < 0 || idx >= fullRows()) {
        const int before = std::max(2, fullRows() / 3);
        auto b = s_->listingBefore(target, before);
        top_ = b.empty() ? target : b[0].addr;
        rowsValid_ = false;
    }
    setCursor(target);
    syncScrollbar();
}

void ListingView::scrollRows(int n) {
    if (n == 0) return;
    ensureRows();
    if (n > 0) {
        const auto count = static_cast<size_t>(n);
        if (count < rows_.size()) {
            top_ = rows_[count].addr;
        } else {
            auto r = s_->listingFrom(top_, n + 1);
            if (!r.empty()) top_ = r[r.size() - 1].addr;
        }
    } else {
        auto r = s_->listingBefore(top_, -n);
        if (!r.empty()) top_ = r[0].addr;
    }
    rowsValid_ = false;
    syncScrollbar();
    viewport()->update();
    scheduleFocusReport();
}

void ListingView::ensureCursorVisible() {
    if (!hasCursor_) return;
    ensureRows();
    const int idx = rowIndexOf(cursor_);
    if (idx >= 0 && idx < fullRows()) return;
    if (cursor_ < top_) {
        top_ = cursor_;
    } else {
        auto b = s_->listingBefore(cursor_, fullRows() - 1);
        top_ = b.empty() ? cursor_ : b[0].addr;
    }
    rowsValid_ = false;
    syncScrollbar();
}

void ListingView::moveCursor(int delta) {
    if (!hasCursor_ || delta == 0) return;
    quint64 next = cursor_;
    if (delta > 0) {
        auto r = s_->listingFrom(cursor_, delta + 1);
        if (!r.empty()) next = r[r.size() - 1].addr;
    } else {
        auto r = s_->listingBefore(cursor_, -delta);
        if (!r.empty()) next = r[0].addr;
    }
    setCursor(next);
    ensureCursorVisible();
}

void ListingView::syncScrollbar() {
    QSignalBlocker block(verticalScrollBar());
    if (total_ == 0) {
        verticalScrollBar()->setRange(0, 0);
        return;
    }
    verticalScrollBar()->setRange(0, kScale);
    const quint64 perPage = static_cast<quint64>(fullRows()) * 4; // ~4 bytes per row
    verticalScrollBar()->setPageStep(
        std::max<int>(1000, static_cast<int>(static_cast<long double>(perPage) / total_ * kScale)));
    verticalScrollBar()->setSingleStep(1);
    const quint64 off = s_->addressToOffset(top_);
    verticalScrollBar()->setValue(
        static_cast<int>(static_cast<long double>(off) / static_cast<long double>(total_) * kScale));
}

void ListingView::onScrollAction(int action) {
    switch (action) {
    case QAbstractSlider::SliderSingleStepAdd: scrollRows(1); break;
    case QAbstractSlider::SliderSingleStepSub: scrollRows(-1); break;
    case QAbstractSlider::SliderPageStepAdd: scrollRows(std::max(1, fullRows() - 1)); break;
    case QAbstractSlider::SliderPageStepSub: scrollRows(-std::max(1, fullRows() - 1)); break;
    case QAbstractSlider::SliderToMinimum:
        top_ = s_->offsetToAddress(0);
        rowsValid_ = false;
        viewport()->update();
        break;
    case QAbstractSlider::SliderToMaximum:
        top_ = s_->offsetToAddress(total_ > 0 ? total_ - 1 : 0);
        rowsValid_ = false;
        viewport()->update();
        scrollRows(-(fullRows() - 2));
        break;
    default: return; // SliderMove is handled by sliderMoved
    }
    QTimer::singleShot(0, this, [this] { syncScrollbar(); });
}

void ListingView::scheduleFocusReport() { focusTimer_.start(); }

int ListingView::labelColumnX() const {
    const int cw = QFontMetrics(font_).horizontalAdvance(QLatin1Char('0'));
    return 14 + (addrWidth_ + 2 + kBytesChars) * cw;
}

void ListingView::paintEvent(QPaintEvent *) {
    QPainter p(viewport());
    const Theme &th = theme();
    p.fillRect(viewport()->rect(), th.background);
    p.setFont(font_);
    hits_.clear();

    if (!s_->isOpen()) {
        p.setPen(th.dim);
        p.drawText(viewport()->rect(), Qt::AlignCenter | Qt::TextWordWrap,
                   tr("No file is open.\nPress Ctrl+K and type \"open <path>\", "
                      "drop a file here, or start with --mock."));
        return;
    }
    ensureRows();
    if (rows_.empty()) {
        p.setPen(th.dim);
        p.drawText(viewport()->rect(), Qt::AlignCenter,
                   tr("Nothing is mapped at this address."));
        return;
    }

    const QFontMetrics fm(font_);
    const int lh = lineHeight();
    const int cw = fm.horizontalAdvance(QLatin1Char('0'));
    const int addrX = 14;
    const int bytesX = addrX + (addrWidth_ + 2) * cw;
    const int labelX = bytesX + kBytesChars * cw;
    const int mnemX = labelX + kLabelChars * cw;
    const int opsX = mnemX + kMnemonicChars * cw;
    const int base = (lh - fm.height()) / 2 + fm.ascent();

    for (size_t i = 0; i < rows_.size(); ++i) {
        const RowDto &r = rows_[i];
        const int y = static_cast<int>(i) * lh;
        if (y > viewport()->height()) break;

        if (hasCursor_ && r.addr == cursor_) {
            p.fillRect(0, y, viewport()->width(), lh, th.cursorRow);
        }
        if (r.is_function) {
            p.setPen(th.separator);
            p.drawLine(0, y, viewport()->width(), y);
        }
        if (r.bookmarked) {
            p.setBrush(th.label);
            p.setPen(Qt::NoPen);
            p.drawEllipse(QPoint(6, y + lh / 2), 3, 3);
        }
        const int ty = y + base;

        p.setPen(th.dim);
        p.drawText(addrX, ty, hexAddr(r.addr, addrWidth_));
        p.drawText(bytesX, ty, qstr(r.bytes));

        if (r.label.size() > 0) {
            QFont f = font_;
            f.setBold(r.is_function);
            p.setFont(f);
            p.setPen(r.is_function ? th.label : th.link);
            const QString lab = fm.elidedText(qstr(r.label), Qt::ElideRight, (kLabelChars - 1) * cw);
            p.drawText(labelX, ty, lab + QLatin1Char(':'));
            p.setFont(font_);
        }

        p.setPen(r.kind == 0 ? th.token(Mnemonic) : th.dim);
        p.drawText(mnemX, ty, qstr(r.mnemonic));

        int x = opsX;
        for (const TokenDto &t : r.tokens) {
            if (x > viewport()->width()) break; // nothing more is visible
            const QString text = qstr(t.text);
            const int w = fm.horizontalAdvance(text);
            const bool linked = t.has_target;
            QFont f = font_;
            if (linked) {
                const QRect rect(x, y, w, lh);
                const bool hot = hover_ >= 0 && static_cast<size_t>(hover_) == hits_.size();
                f.setUnderline(hot);
                hits_.push_back({rect, t.target});
                p.setPen(th.link);
            } else {
                p.setPen(th.token(t.kind));
            }
            p.setFont(f);
            p.drawText(x, ty, text);
            x += w;
        }
        p.setFont(font_);
        if (r.comment.size() > 0) {
            p.setPen(th.token(Comment));
            p.drawText(x + 2 * cw, ty, QStringLiteral("; ") + qstr(r.comment));
        }
    }
}

void ListingView::resizeEvent(QResizeEvent *e) {
    QAbstractScrollArea::resizeEvent(e);
    rowsValid_ = false;
    if (s_->isOpen()) syncScrollbar();
}

void ListingView::wheelEvent(QWheelEvent *e) {
    wheelRemainder_ += e->angleDelta().y();
    const int steps = wheelRemainder_ / 120;
    wheelRemainder_ -= steps * 120;
    if (steps != 0) scrollRows(-steps * kWheelRowsPerStep);
    e->accept();
}

void ListingView::keyPressEvent(QKeyEvent *e) {
    if (!s_->isOpen()) return;
    switch (e->key()) {
    case Qt::Key_Up: moveCursor(-1); break;
    case Qt::Key_Down: moveCursor(1); break;
    case Qt::Key_PageUp: moveCursor(-std::max(1, fullRows() - 1)); break;
    case Qt::Key_PageDown: moveCursor(std::max(1, fullRows() - 1)); break;
    case Qt::Key_Home: goTo(s_->offsetToAddress(0)); break;
    case Qt::Key_End: {
        goTo(s_->offsetToAddress(total_ > 0 ? total_ - 1 : 0));
        break;
    }
    case Qt::Key_Return:
    case Qt::Key_Enter: followCursor(); break;
    default: QAbstractScrollArea::keyPressEvent(e); return;
    }
    e->accept();
}

void ListingView::followCursor() {
    const int idx = rowIndexOf(cursor_);
    if (idx < 0) return;
    for (const TokenDto &t : rows_[static_cast<size_t>(idx)].tokens) {
        if (t.has_target) {
            emit jumpRequested(t.target);
            return;
        }
    }
}

void ListingView::mousePressEvent(QMouseEvent *e) {
    setFocus();
    if (e->button() != Qt::LeftButton || !s_->isOpen()) return;
    const QPoint pos = e->position().toPoint();
    ensureRows();
    const int row = pos.y() / lineHeight();
    if (row < 0 || static_cast<size_t>(row) >= rows_.size()) return;
    for (const Hit &h : hits_) {
        if (h.rect.contains(pos)) {
            setCursor(rows_[static_cast<size_t>(row)].addr);
            emit jumpRequested(h.target);
            return;
        }
    }
    setCursor(rows_[static_cast<size_t>(row)].addr);
}

void ListingView::mouseDoubleClickEvent(QMouseEvent *e) {
    if (e->button() == Qt::LeftButton) beginRename();
}

void ListingView::mouseMoveEvent(QMouseEvent *e) {
    int hot = -1;
    const QPoint pos = e->position().toPoint();
    for (size_t i = 0; i < hits_.size(); ++i) {
        if (hits_[i].rect.contains(pos)) {
            hot = static_cast<int>(i);
            break;
        }
    }
    if (hot != hover_) {
        hover_ = hot;
        viewport()->setCursor(hot >= 0 ? Qt::PointingHandCursor : Qt::ArrowCursor);
        viewport()->update();
    }
}

void ListingView::leaveEvent(QEvent *) {
    if (hover_ != -1) {
        hover_ = -1;
        viewport()->update();
    }
}

void ListingView::beginRename() { beginEdit(EditMode::Rename); }
void ListingView::beginComment() { beginEdit(EditMode::Comment); }

void ListingView::beginEdit(EditMode mode) {
    if (!hasCursor_ || !s_->isOpen()) return;
    ensureCursorVisible();
    ensureRows();
    const int idx = rowIndexOf(cursor_);
    if (idx < 0) return;
    const RowDto &r = rows_[static_cast<size_t>(idx)];
    editMode_ = mode;
    editAddr_ = r.addr;
    if (mode == EditMode::Rename) {
        edit_->setText(qstr(r.label));
        edit_->setPlaceholderText(tr("New name (empty resets)"));
        const quint32 refs = s_->xrefCountTo(r.addr);
        hint_->setText(tr("%1 reference(s) will show the new name. Enter applies, Esc cancels.")
                           .arg(refs));
    } else {
        edit_->setText(qstr(r.comment));
        edit_->setPlaceholderText(tr("Comment (empty removes)"));
        hint_->setText(tr("Enter saves, Esc cancels."));
    }
    editor_->setFixedWidth(std::min(520, viewport()->width() - 20));
    editor_->adjustSize();
    int y = (idx + 1) * lineHeight();
    if (y + editor_->height() > viewport()->height()) y = idx * lineHeight() - editor_->height();
    editor_->move(std::max(4, std::min(labelColumnX(), viewport()->width() - editor_->width() - 4)),
                  std::max(0, y));
    editor_->show();
    editor_->raise();
    edit_->setFocus();
    edit_->selectAll();
}

void ListingView::endEdit(bool apply) {
    if (!editor_->isVisible()) return;
    const QString text = edit_->text();
    editor_->hide();
    setFocus();
    if (!apply) return;
    const QString err = editMode_ == EditMode::Rename ? s_->rename(editAddr_, text)
                                                       : s_->setComment(editAddr_, text);
    if (!err.isEmpty()) emit message(err);
}

bool ListingView::eventFilter(QObject *obj, QEvent *ev) {
    if (obj == edit_) {
        if (ev->type() == QEvent::KeyPress &&
            static_cast<QKeyEvent *>(ev)->key() == Qt::Key_Escape) {
            endEdit(false);
            return true;
        }
        if (ev->type() == QEvent::FocusOut && editor_->isVisible()) {
            endEdit(false);
        }
    }
    return QAbstractScrollArea::eventFilter(obj, ev);
}

} // namespace dasm
