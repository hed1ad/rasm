#pragma once
// Virtualized linear listing.
//
// The view keeps only a few numbers (top address, cursor, scrollbar scale)
// and asks the snapshot for the rows that are on screen, so its cost does
// not depend on the size of the binary. The vertical scrollbar maps linearly
// onto *mapped bytes*; stepping (wheel, arrows, PgUp/PgDn) walks items with
// Snapshot::listing_from / listing_before in both directions.

#include <QAbstractScrollArea>
#include <QList>
#include <QPair>
#include <QRect>
#include <QTimer>
#include <vector>

#include "Common.h"

class QFrame;
class QLabel;
class QLineEdit;

namespace dasm {

class ListingView : public QAbstractScrollArea {
    Q_OBJECT
public:
    ListingView(SessionObject *session, QWidget *parent = nullptr);

    bool hasCursor() const { return hasCursor_; }
    quint64 cursor() const { return cursor_; }
    quint64 topAddress() const { return top_; }
    // Rows currently laid out (for tests and the status bar).
    int rowCount() const { return static_cast<int>(rows_.size()); }
    QString rowMnemonic(int i) const;
    quint64 rowAddress(int i) const;
    QString rowLabel(int i) const;
    int lineHeight() const;
    int visibleRowCount() const;
    // Clickable operand rectangles of the last paint (viewport coordinates).
    QList<QPair<QRect, quint64>> linkHits() const;

    // Scrolls so that `addr` is visible and puts the cursor on it.
    void goTo(quint64 addr);
    // Called after a session was opened: recomputes ranges, shows the entry.
    void reload();
    // Called on a new snapshot: drops the row cache and repaints.
    void invalidate();

    void scrollRows(int rows);
    void moveCursor(int rows);
    void beginRename();
    void beginComment();
    // Follows the first linked operand of the cursor row.
    void followCursor();
    bool editing() const;

signals:
    // The user asked to navigate; the caller records history and calls goTo.
    void jumpRequested(quint64 target);
    void cursorMoved(quint64 addr);
    void message(const QString &text);

protected:
    void paintEvent(QPaintEvent *) override;
    void resizeEvent(QResizeEvent *) override;
    void wheelEvent(QWheelEvent *) override;
    void keyPressEvent(QKeyEvent *) override;
    void mousePressEvent(QMouseEvent *) override;
    void mouseMoveEvent(QMouseEvent *) override;
    void mouseDoubleClickEvent(QMouseEvent *) override;
    void leaveEvent(QEvent *) override;
    bool eventFilter(QObject *, QEvent *) override;

private:
    struct Hit {
        QRect rect;
        quint64 target;
    };
    enum class EditMode { Rename, Comment };

    int fullRows() const;
    void ensureRows();
    void fetchRows(quint64 from, int count);
    int rowIndexOf(quint64 addr) const;
    void ensureCursorVisible();
    void setCursor(quint64 addr);
    void syncScrollbar();
    void onScrollAction(int action);
    void scheduleFocusReport();
    void beginEdit(EditMode mode);
    void endEdit(bool apply);
    int labelColumnX() const;

    SessionObject *s_;
    quint64 top_ = 0;
    quint64 cursor_ = 0;
    bool hasCursor_ = false;
    quint64 total_ = 0;
    int addrWidth_ = 16;

    rust::Vec<RowDto> rows_;
    bool rowsValid_ = false;
    quint64 rowsTop_ = 0;
    int rowsWanted_ = 0;

    std::vector<Hit> hits_;
    int hover_ = -1;
    int wheelRemainder_ = 0;

    QFont font_;
    QTimer focusTimer_;

    QFrame *editor_ = nullptr;
    QLineEdit *edit_ = nullptr;
    QLabel *hint_ = nullptr;
    EditMode editMode_ = EditMode::Rename;
    quint64 editAddr_ = 0;
};

} // namespace dasm
