// ctest smoke: open the synthetic program, drive the main flows through the
// public widgets, save a screenshot, exit 0 on success.

#include <QApplication>
#include <QSignalSpy>
#include <QStatusBar>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QTimer>
#include <cstdio>
#include <functional>

#include "ListPanel.h"
#include "ListingView.h"
#include "MainWindow.h"
#include "Palette.h"

namespace {
int failures = 0;

#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
            ++failures;                                                              \
        }                                                                            \
    } while (0)

bool waitFor(const std::function<bool()> &pred, int ms = 5000) {
    QElapsedTimer t;
    t.start();
    while (!pred()) {
        if (t.elapsed() > ms) return false;
        QEventLoop loop;
        QTimer::singleShot(10, &loop, &QEventLoop::quit);
        loop.exec();
    }
    return true;
}
} // namespace

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    dasm::applyTheme();
    const QString shot = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();

    dasm::MainWindow win;
    win.show();
    bool opened = false;
    QObject::connect(&win.session(), &SessionObject::opened, [&] { opened = true; });
    win.openMock();
    CHECK(waitFor([&] { return opened; }));
    CHECK(win.session().isOpen());

    // Listing starts at the entry point and has rows.
    auto *lv = win.listing();
    CHECK(lv->hasCursor());
    CHECK(waitFor([&] { return lv->rowCount() > 0; }));
    CHECK(lv->rowAddress(0) <= lv->cursor());
    CHECK(!lv->rowMnemonic(0).isEmpty());

    // Tables are populated and filterable.
    win.refreshListsNow();
    CHECK(win.functionsPanel()->sourceRows() >= 3);
    CHECK(win.stringsPanel()->sourceRows() >= 2);
    CHECK(win.importsPanel()->sourceRows() >= 1);
    win.functionsPanel()->setFilter(QStringLiteral("main"));
    CHECK(win.functionsPanel()->visibleRows() >= 1);
    CHECK(win.functionsPanel()->visibleRows() < win.functionsPanel()->sourceRows());
    win.functionsPanel()->setFilter(QString());

    // Scrolling in both directions.
    const quint64 top0 = lv->topAddress();
    lv->scrollRows(3);
    CHECK(lv->topAddress() > top0);
    lv->scrollRows(-3);
    CHECK(lv->topAddress() == top0);

    // Navigation history.
    const quint64 start = lv->cursor();
    win.navigate(0x402000);
    CHECK(lv->cursor() == 0x402000);
    CHECK(win.commands().run(QStringLiteral("nav.back")));
    CHECK(lv->cursor() == start);
    CHECK(win.commands().run(QStringLiteral("nav.forward")));
    CHECK(lv->cursor() == 0x402000);
    win.navigate(start);

    // Rename + undo through the session (the command path).
    const quint64 mainAddr = win.session().functionStart(start);
    CHECK(win.session().rename(mainAddr, QStringLiteral("my_entry")).isEmpty());
    CHECK(waitFor([&] { return win.session().nameAt(mainAddr) == QStringLiteral("my_entry"); }));
    CHECK(waitFor([&] { return win.commands().find(QStringLiteral("edit.undo"))->action->isEnabled(); }));
    CHECK(win.commands().run(QStringLiteral("edit.undo")));
    CHECK(waitFor([&] { return win.session().nameAt(mainAddr) != QStringLiteral("my_entry"); }));
    CHECK(!win.session().rename(mainAddr, QStringLiteral("bad name")).isEmpty()); // rejected, no dialog

    // Palette finds commands and functions.
    CHECK(!win.palette()->search(QStringLiteral("undo")).empty());
    CHECK(!win.palette()->search(QStringLiteral("main")).empty());
    CHECK(win.palette()->search(QString()).size() >= 10);
    CHECK(dasm::Palette::fuzzyScore(QStringLiteral("gtd"), QStringLiteral("Go to address")) >= 0);
    CHECK(dasm::Palette::fuzzyScore(QStringLiteral("zzz"), QStringLiteral("Go to address")) < 0);

    // A failing open reports in the status bar (no dialog) and keeps the session.
    QSignalSpy errors(&win.session(), &SessionObject::errorOccurred);
    win.openFile(QStringLiteral("/nonexistent"));
    CHECK(waitFor([&] { return errors.count() == 1; }));
    CHECK(win.statusBar()->currentMessage().contains(QStringLiteral("cannot open")));
    CHECK(win.session().isOpen());

    if (!shot.isEmpty()) {
        win.palette()->openWith(QStringLiteral("ma"));
        QApplication::processEvents();
        CHECK(win.grab().save(shot));
        win.palette()->hide();
    }
    if (failures) std::fprintf(stderr, "%d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
