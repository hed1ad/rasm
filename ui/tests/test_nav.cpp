// 14: NavHistory (Alt+Left / Alt+Right list).
#include <QTest>

#include "MainWindow.h"

using dasm::NavHistory;

class TestNav : public QObject {
    Q_OBJECT
private slots:
    void emptyHistoryIsSafe() {
        NavHistory h;
        QVERIFY(!h.canBack());
        QVERIFY(!h.canForward());
        QCOMPARE(h.back(), quint64(0)); // must not crash
        QCOMPARE(h.forward(), quint64(0));
        QCOMPARE(h.size(), size_t(0));
    }

    void backAndForwardStopAtTheEdges() {
        NavHistory h;
        h.visit(1);
        h.visit(2);
        h.visit(3);
        QVERIFY(h.canBack());
        QVERIFY(!h.canForward());
        QCOMPARE(h.forward(), quint64(3)); // at the newest: stays
        QCOMPARE(h.back(), quint64(2));
        QCOMPARE(h.back(), quint64(1));
        QVERIFY(!h.canBack());
        QCOMPARE(h.back(), quint64(1)); // at the oldest: stays
        QVERIFY(h.canForward());
        QCOMPARE(h.forward(), quint64(2));
        QCOMPARE(h.forward(), quint64(3));
        QVERIFY(!h.canForward());
    }

    void visitAfterBackDropsTheForwardTail() {
        NavHistory h;
        h.visit(1);
        h.visit(2);
        h.visit(3);
        h.back();
        h.back();
        h.visit(9);
        QCOMPARE(h.size(), size_t(2)); // 1, 9
        QVERIFY(!h.canForward());
        QCOMPARE(h.back(), quint64(1));
        QCOMPARE(h.forward(), quint64(9));
    }

    void visitingTheSameAddressTwiceDoesNothing() {
        NavHistory h;
        h.visit(5);
        h.visit(5);
        QCOMPARE(h.size(), size_t(1));
        h.visit(6);
        h.visit(6);
        QCOMPARE(h.size(), size_t(2));
        h.back();
        h.visit(5); // current entry is 5: no change, tail kept
        QCOMPARE(h.size(), size_t(2));
        QVERIFY(h.canForward());
    }

    void updateCurrentRewritesOnlyTheCurrentEntry() {
        NavHistory h;
        h.updateCurrent(7); // empty: creates the first entry
        QCOMPARE(h.size(), size_t(1));
        h.visit(8);
        h.updateCurrent(10);
        QCOMPARE(h.size(), size_t(2));
        QCOMPARE(h.back(), quint64(7));
        QCOMPARE(h.forward(), quint64(10));
    }
};

QTEST_MAIN(TestNav)
#include "test_nav.moc"
