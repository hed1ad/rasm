// 16: rename and comment through the UI, undo, history panel.
#include <QFocusEvent>
#include <QLineEdit>
#include <QListWidget>
#include <QSignalSpy>
#include <QTest>

#include "ListPanel.h"
#include "ListingView.h"
#include "TestUtil.h"

using dasm::ListingView;

class TestEditing : public QObject {
    Q_OBJECT

    std::unique_ptr<dasm::MainWindow> win_;
    ListingView *lv_ = nullptr;
    SessionObject *s_ = nullptr;

    QLineEdit *editor() { return lv_->findChild<QLineEdit *>(); }
    QString nameAt(quint64 a) { return s_->nameAt(a); }
    QString commentAt(quint64 a) {
        auto rows = s_->listingFrom(a, 1);
        return rows.empty() ? QString() : dasm::qstr(rows[0].comment);
    }
    bool undoEnabled() { return win_->commands().find(QStringLiteral("edit.undo"))->action->isEnabled(); }

private slots:
    void init() {
        win_ = dasmtest::openedWindow();
        QVERIFY(win_);
        lv_ = win_->listing();
        s_ = &win_->session();
        lv_->goTo(0x401010); // main
        lv_->setFocus();
        QApplication::processEvents();
    }

    void renameWithNThenEnterThenUndo() {
        QCOMPARE(nameAt(0x401010), QStringLiteral("main"));
        QTest::keyClick(lv_, Qt::Key_N);
        QVERIFY(lv_->editing());
        QLineEdit *e = editor();
        QVERIFY(e);
        QCOMPARE(e->text(), QStringLiteral("main")); // prefilled with the current name
        e->setText(QStringLiteral("renamed_main"));
        QTest::keyClick(e, Qt::Key_Return);
        QVERIFY(!lv_->editing());
        QTRY_COMPARE(nameAt(0x401010), QStringLiteral("renamed_main"));

        // The History panel lists the entry (newest first).
        QTRY_VERIFY(undoEnabled());
        win_->refreshListsNow();
        auto *hist = win_->historyList();
        QCOMPARE(hist->count(), 1);
        QVERIFY(hist->item(0)->text().contains(QStringLiteral("Rename")));
        QVERIFY(hist->item(0)->text().contains(QStringLiteral("renamed_main")));
        QVERIFY(!hist->item(0)->font().strikeOut());
        // The symbol is visible in the functions table.
        bool found = false;
        auto *panel = win_->functionsPanel();
        panel->setFilter(QStringLiteral("renamed_main"));
        found = panel->visibleRows() == 1;
        panel->setFilter(QString());
        QVERIFY(found);

        // Ctrl+Z through the command.
        QVERIFY(win_->commands().run(QStringLiteral("edit.undo")));
        QTRY_COMPARE(nameAt(0x401010), QStringLiteral("main"));
        QTRY_VERIFY(!undoEnabled());
        win_->refreshListsNow();
        QCOMPARE(hist->count(), 1);
        QVERIFY(hist->item(0)->font().strikeOut()); // shown as undone
        QVERIFY(win_->commands().find(QStringLiteral("edit.redo"))->action->isEnabled());

        QVERIFY(win_->commands().run(QStringLiteral("edit.redo")));
        QTRY_COMPARE(nameAt(0x401010), QStringLiteral("renamed_main"));
    }

    QString listingLabelAt(quint64 addr) {
        win_->grab(); // paints, which fetches rows from the newest snapshot
        for (int i = 0; i < lv_->rowCount(); ++i) {
            if (lv_->rowAddress(i) == addr) return lv_->rowLabel(i);
        }
        return QStringLiteral("<not visible>");
    }

    // The signal path: new snapshot -> listing repaint, tables, history.
    // Nothing here calls refreshListsNow() or repaints by hand.
    void viewsFollowNewSnapshots() {
        win_->grab();
        QCOMPARE(listingLabelAt(0x401010), QStringLiteral("main"));
        QVERIFY(s_->rename(0x401010, QStringLiteral("live_name")).isEmpty());
        QTRY_COMPARE(listingLabelAt(0x401010), QStringLiteral("live_name"));
        win_->functionsPanel()->setFilter(QStringLiteral("live_name"));
        QTRY_COMPARE(win_->functionsPanel()->visibleRows(), 1);
        win_->functionsPanel()->setFilter(QString());
        QTRY_COMPARE(win_->historyList()->count(), 1);
        QVERIFY(win_->commands().run(QStringLiteral("edit.undo")));
        QTRY_COMPARE(listingLabelAt(0x401010), QStringLiteral("main"));
    }

    void reopenResetsNavigationAndViews() {
        win_->navigate(0x402000);
        win_->navigate(0x401010);
        QVERIFY(win_->nav().size() >= 2);
        QVERIFY(s_->rename(0x401010, QStringLiteral("old_session_name")).isEmpty());
        QSignalSpy opened(s_, &SessionObject::opened);
        win_->openMock();
        QTRY_COMPARE(opened.count(), 1);
        QCOMPARE(win_->nav().size(), size_t(1));
        QVERIFY(!win_->nav().canBack());
        QCOMPARE(lv_->cursor(), quint64(0x401000)); // back at the entry point
        QVERIFY(win_->functionsPanel()->sourceRows() >= 3);
        QVERIFY(win_->importsPanel()->sourceRows() >= 1);
        QCOMPARE(nameAt(0x401010), QStringLiteral("main")); // fresh session
        QTRY_VERIFY(!undoEnabled());
    }

    void ctrlZShortcutIsWired() {
        QVERIFY(s_->rename(0x401010, QStringLiteral("tmp_name")).isEmpty());
        QTRY_VERIFY(undoEnabled());
        QTest::keyClick(win_.get(), Qt::Key_Z, Qt::ControlModifier);
        QTRY_COMPARE(nameAt(0x401010), QStringLiteral("main"));
    }

    void escapeAppliesNothing() {
        QTest::keyClick(lv_, Qt::Key_N);
        QVERIFY(lv_->editing());
        editor()->setText(QStringLiteral("should_not_apply"));
        QTest::keyClick(editor(), Qt::Key_Escape);
        QVERIFY(!lv_->editing());
        QApplication::processEvents();
        QCOMPARE(nameAt(0x401010), QStringLiteral("main"));
        QVERIFY(!undoEnabled());
        QCOMPARE(win_->historyList()->count(), 0);
    }

    void focusLossAppliesNothing() {
        QTest::keyClick(lv_, Qt::Key_N);
        QVERIFY(lv_->editing());
        editor()->setText(QStringLiteral("should_not_apply"));
        QFocusEvent out(QEvent::FocusOut);
        QApplication::sendEvent(editor(), &out);
        QVERIFY(!lv_->editing());
        QApplication::processEvents();
        QCOMPARE(nameAt(0x401010), QStringLiteral("main"));
        QVERIFY(!undoEnabled());
    }

    void invalidNameIsReportedNotApplied() {
        QTest::keyClick(lv_, Qt::Key_N);
        QSignalSpy msg(lv_, &ListingView::message);
        editor()->setText(QStringLiteral("two words"));
        QTest::keyClick(editor(), Qt::Key_Return);
        QCOMPARE(msg.count(), 1);
        QVERIFY(!msg.at(0).at(0).toString().isEmpty());
        QCOMPARE(nameAt(0x401010), QStringLiteral("main"));
        QVERIFY(!lv_->editing());
    }

    void emptyNameResetsTheName() {
        QVERIFY(s_->rename(0x401010, QStringLiteral("custom")).isEmpty());
        QTRY_COMPARE(nameAt(0x401010), QStringLiteral("custom"));
        QTest::keyClick(lv_, Qt::Key_N);
        editor()->clear();
        QTest::keyClick(editor(), Qt::Key_Return);
        QTRY_COMPARE(nameAt(0x401010), QStringLiteral("main"));
    }

    void commentWithSemicolon() {
        lv_->goTo(0x401011);
        QTest::keyClick(lv_, Qt::Key_Semicolon);
        QVERIFY(lv_->editing());
        editor()->setText(QStringLiteral("frame setup"));
        QTest::keyClick(editor(), Qt::Key_Return);
        QTRY_COMPARE(commentAt(0x401011), QStringLiteral("frame setup"));
        QTRY_VERIFY(undoEnabled());
        win_->refreshListsNow();
        QVERIFY(win_->historyList()->item(0)->text().contains(QStringLiteral("Comment")));

        // Editing again is prefilled; an empty text removes the comment.
        QTest::keyClick(lv_, Qt::Key_Semicolon);
        QCOMPARE(editor()->text(), QStringLiteral("frame setup"));
        editor()->clear();
        QTest::keyClick(editor(), Qt::Key_Return);
        QTRY_COMPARE(commentAt(0x401011), QString());

        QVERIFY(win_->commands().run(QStringLiteral("edit.undo")));
        QTRY_COMPARE(commentAt(0x401011), QStringLiteral("frame setup"));
    }

    void doubleClickStartsRename() {
        lv_->goTo(0x401010);
        win_->grab();
        QTest::mouseDClick(lv_->viewport(), Qt::LeftButton, {}, QPoint(30, 3 * 18 + 2));
        QVERIFY(lv_->editing());
        QTest::keyClick(editor(), Qt::Key_Escape);
        QVERIFY(!lv_->editing());
    }

    void renameOnPaletteCommandWithoutFileDoesNothing() {
        dasm::MainWindow bare;
        bare.show();
        bare.listing()->beginRename(); // no cursor, nothing open
        QVERIFY(!bare.listing()->editing());
        QVERIFY(!bare.session().rename(0x401010, QStringLiteral("x")).isEmpty());
        QVERIFY(!bare.session().undo().isEmpty());
    }
};

QTEST_MAIN(TestEditing)
#include "test_editing.moc"
