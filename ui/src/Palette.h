#pragma once
// Ctrl+K command palette: commands, functions, strings, addresses and
// "open <path>" in one fuzzy search box. A frameless child widget of the
// main window, never a modal dialog.

#include <QFrame>
#include <vector>

#include "Common.h"

class QLineEdit;
class QListWidget;

namespace dasm {

class CommandRegistry;
class FunctionsModel;
class StringsModel;

class Palette : public QFrame {
    Q_OBJECT
public:
    enum class Kind { Command, Function, String, Address, OpenFile };

    struct Result {
        Kind kind;
        QString title;
        QString hint; // shortcut or address
        QString commandId;
        quint64 addr = 0;
        QString path;
    };

    Palette(SessionObject *session, CommandRegistry *commands, FunctionsModel *functions,
            StringsModel *strings, QWidget *parent);

    // Shows the palette with `prefill` in the search box.
    void openWith(const QString &prefill = {});
    std::vector<Result> search(const QString &query) const;
    int resultCount() const;
    void setQuery(const QString &q);
    void activateCurrent();

    // Subsequence match score, -1 if `pattern` is not a subsequence of `text`.
    static int fuzzyScore(const QString &pattern, const QString &text);
    // Parses "0x401000" or a bare hex number of at least 4 digits.
    static bool parseAddress(const QString &text, quint64 *out);

signals:
    void navigateTo(quint64 addr);
    void openFile(const QString &path);

protected:
    bool eventFilter(QObject *, QEvent *) override;

private:
    void refresh();
    void reposition();

    SessionObject *s_;
    CommandRegistry *commands_;
    FunctionsModel *functions_;
    StringsModel *strings_;
    QLineEdit *edit_;
    QListWidget *list_;
    std::vector<Result> results_;
};

} // namespace dasm
