// 13: command palette (fuzzy score, address parsing, modes, keyboard).
#include <QFocusEvent>
#include <QLineEdit>
#include <QListWidget>
#include <QSignalSpy>
#include <QTest>

#include "ListingView.h"
#include "Palette.h"
#include "TestUtil.h"

using dasm::Palette;

class TestPalette : public QObject {
    Q_OBJECT

    static bool hasCommand(const std::vector<Palette::Result> &r, const QString &id) {
        for (const auto &x : r) {
            if (x.kind == Palette::Kind::Command && x.commandId == id) return true;
        }
        return false;
    }

private slots:
    void fuzzyRanking() {
        const auto s = [](const char *p, const char *t) {
            return Palette::fuzzyScore(QString::fromLatin1(p), QString::fromLatin1(t));
        };
        QCOMPARE(s("", "anything"), 0);
        QCOMPARE(s("zzz", "Go to address"), -1);
        QCOMPARE(s("ia", "main"), -1); // order matters
        QVERIFY(s("mn", "main") >= 0);
        QVERIFY(s("ain", "main") >= 0);
        // Prefix and consecutive matches beat scattered ones.
        QVERIFY(s("ren", "Rename") > s("ren", "Go to entry point"));
        QVERIFY(s("main", "main") > s("main", "remaining_data"));
        QVERIFY(s("go", "Go to address") > s("go", "Show strings go"));
        // Case-insensitive; spaces in the pattern are ignored.
        QCOMPARE(s("MAIN", "main"), s("main", "main"));
        QCOMPARE(s("go to", "Go to address"), s("goto", "Go to address"));
        // A shorter text wins on equal matches.
        QVERIFY(s("ab", "ab") > s("ab", "ab_____________________"));
    }

    void parseAddress() {
        quint64 v = 0;
        QVERIFY(Palette::parseAddress(QStringLiteral("dead"), &v));
        QCOMPARE(v, quint64(0xdead));
        QVERIFY(Palette::parseAddress(QStringLiteral("0x401000"), &v));
        QCOMPARE(v, quint64(0x401000));
        QVERIFY(Palette::parseAddress(QStringLiteral("  0X10  "), &v));
        QCOMPARE(v, quint64(0x10));
        QVERIFY(Palette::parseAddress(QStringLiteral("0x1"), &v));
        QVERIFY(Palette::parseAddress(QStringLiteral("0xffffffffffffffff"), &v));
        QCOMPARE(v, quint64(UINT64_MAX));
        // Rejected.
        QVERIFY(!Palette::parseAddress(QStringLiteral("dea"), &v)); // bare: needs 4 digits
        QVERIFY(!Palette::parseAddress(QStringLiteral("0x"), &v));
        QVERIFY(!Palette::parseAddress(QString(), &v));
        QVERIFY(!Palette::parseAddress(QStringLiteral("xyz1"), &v));
        QVERIFY(!Palette::parseAddress(QStringLiteral("0xzz"), &v));
        QVERIFY(!Palette::parseAddress(QStringLiteral("0x401000 main"), &v));
        QVERIFY(!Palette::parseAddress(QStringLiteral("0x1ffffffffffffffff"), &v)); // overflow
        QVERIFY(!Palette::parseAddress(QStringLiteral("fffffffffffffffff"), &v));
        QVERIFY(!Palette::parseAddress(QStringLiteral("-0x10"), &v));
    }

    void searchModes() {
        auto win = dasmtest::openedWindow();
        QVERIFY(win);
        Palette *p = win->palette();

        auto open = p->search(QStringLiteral("open /tmp/some file.elf"));
        QVERIFY(!open.empty());
        QCOMPARE(open[0].kind, Palette::Kind::OpenFile);
        QCOMPARE(open[0].path, QStringLiteral("/tmp/some file.elf"));
        for (const auto &r : p->search(QStringLiteral("open "))) {
            QVERIFY(r.kind != Palette::Kind::OpenFile); // no path yet
        }

        auto addr = p->search(QStringLiteral("0x402000"));
        QVERIFY(!addr.empty());
        QCOMPARE(addr[0].kind, Palette::Kind::Address);
        QCOMPARE(addr[0].addr, quint64(0x402000));
        auto unmapped = p->search(QStringLiteral("0xdead0000"));
        QCOMPARE(unmapped[0].kind, Palette::Kind::Address); // still offered, labelled unmapped

        bool fn = false, str = false;
        for (const auto &r : p->search(QStringLiteral("main"))) fn |= r.kind == Palette::Kind::Function;
        for (const auto &r : p->search(QStringLiteral("hello"))) str |= r.kind == Palette::Kind::String;
        QVERIFY(fn);
        QVERIFY(str);
        // Short queries do not search strings.
        for (const auto &r : p->search(QStringLiteral("he"))) {
            QVERIFY(r.kind != Palette::Kind::String);
        }
        // Empty query lists commands only.
        const auto all = p->search(QString());
        QVERIFY(all.size() >= 10);
        for (const auto &r : all) QCOMPARE(r.kind, Palette::Kind::Command);
    }

    void disabledCommandsAreHidden() {
        auto win = dasmtest::openedWindow();
        QVERIFY(win);
        Palette *p = win->palette();
        auto *undo = win->commands().find(QStringLiteral("edit.undo"));
        QVERIFY(undo && !undo->action->isEnabled());
        QVERIFY(!hasCommand(p->search(QStringLiteral("undo")), QStringLiteral("edit.undo")));
        QVERIFY(!hasCommand(p->search(QString()), QStringLiteral("edit.undo")));

        QVERIFY(win->session().rename(0x401010, QStringLiteral("x")).isEmpty());
        QTRY_VERIFY(undo->action->isEnabled());
        QVERIFY(hasCommand(p->search(QStringLiteral("undo")), QStringLiteral("edit.undo")));
        QVERIFY(hasCommand(p->search(QString()), QStringLiteral("edit.undo")));
    }

    void keyboardAndFocus() {
        auto win = dasmtest::openedWindow();
        QVERIFY(win);
        Palette *p = win->palette();
        auto *edit = p->findChild<QLineEdit *>();
        auto *list = p->findChild<QListWidget *>();
        QVERIFY(edit && list);

        p->openWith();
        QVERIFY(p->isVisible());
        const int n = list->count();
        QVERIFY(n >= 2);
        QCOMPARE(list->currentRow(), 0);
        QTest::keyClick(edit, Qt::Key_Up); // wraps to the last
        QCOMPARE(list->currentRow(), n - 1);
        QTest::keyClick(edit, Qt::Key_Down); // wraps to the first
        QCOMPARE(list->currentRow(), 0);
        QTest::keyClick(edit, Qt::Key_Down);
        QCOMPARE(list->currentRow(), 1);
        QTest::keyClick(edit, Qt::Key_PageUp);
        QCOMPARE(list->currentRow(), 0);
        QTest::keyClick(edit, Qt::Key_PageDown);
        QCOMPARE(list->currentRow(), qMin(n - 1, 8));

        QTest::keyClick(edit, Qt::Key_Escape);
        QVERIFY(!p->isVisible());

        p->openWith();
        QVERIFY(p->isVisible());
        QFocusEvent out(QEvent::FocusOut);
        QApplication::sendEvent(edit, &out);
        QVERIFY(!p->isVisible());

        // Enter on an address result navigates and closes the palette.
        p->openWith(QStringLiteral("0x402000"));
        QCOMPARE(list->currentRow(), 0);
        QTest::keyClick(edit, Qt::Key_Return);
        QVERIFY(!p->isVisible());
        QCOMPARE(win->listing()->cursor(), quint64(0x402000));
    }

    void enterOnOpenFileEmitsTheSignal() {
        auto win = dasmtest::openedWindow();
        QVERIFY(win);
        QSignalSpy spy(win->palette(), &Palette::openFile);
        // Do not call MainWindow::openFile here (no backend): use the palette alone.
        win->palette()->disconnect(win.get());
        win->palette()->openWith(QStringLiteral("open /tmp/x.elf"));
        QTest::keyClick(win->palette()->findChild<QLineEdit *>(), Qt::Key_Return);
        QCOMPARE(spy.count(), 1);
        QCOMPARE(spy.at(0).at(0).toString(), QStringLiteral("/tmp/x.elf"));
    }
};

QTEST_MAIN(TestPalette)
#include "test_palette.moc"
