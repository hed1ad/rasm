// 8, 9: snapshot-change coalescing and teardown races of SessionObject.
// (10, re-open unsubscribes the old session, is a Rust unit test in
// crates/dasm-qt/src/bridge.rs: it needs no event loop.)
#include <QSignalSpy>
#include <QTest>
#include <memory>

#include "TestUtil.h"

class TestBridge : public QObject {
    Q_OBJECT
private slots:
    void burstsAreCoalescedAndTheLastSignalIsCurrent() {
        SessionObject s;
        QVERIFY(dasmtest::openMock(s));
        QApplication::processEvents();
        const quint64 g0 = s.status().generation;

        QSignalSpy spy(&s, &SessionObject::snapshotChanged);
        // 8 threads x 1250 publications = 10000, finished before the event
        // loop runs again: at most one notification can be queued.
        const quint64 g1 = s.diagPublish(8, 1250, true);
        QCOMPARE(g1, g0 + 10000);
        QApplication::processEvents();
        QTRY_VERIFY(spy.count() >= 1);
        QVERIFY2(spy.count() <= 2, qPrintable(QString::number(spy.count())));
        QCOMPARE(spy.last().at(0).toULongLong(), g1);
        QCOMPARE(s.status().generation, g1);

        // After the burst a later publication is notified again (pending reset).
        spy.clear();
        const quint64 g2 = s.diagPublish(1, 1, true);
        QTRY_COMPARE(spy.count(), 1);
        QCOMPARE(spy.last().at(0).toULongLong(), g2);
    }

    void concurrentBurstWhileTheLoopRuns() {
        SessionObject s;
        QVERIFY(dasmtest::openMock(s));
        QSignalSpy spy(&s, &SessionObject::snapshotChanged);
        quint64 last = 0;
        QObject::connect(&s, &SessionObject::snapshotChanged, [&](quint64 g) {
            QVERIFY(g >= last); // generations never go backwards
            last = g;
        });
        const quint64 start = s.status().generation;
        s.diagPublish(4, 2500, false); // runs in the background
        QTRY_COMPARE_WITH_TIMEOUT(s.status().generation, start + 10000, 20000);
        QTRY_COMPARE(last, start + 10000);
        QVERIFY(spy.count() >= 1);
        QVERIFY(spy.count() <= 10000);
    }

    void destroyingTheObjectWhilePublicationsContinue() {
        for (int round = 0; round < 20; ++round) {
            auto s = std::make_unique<SessionObject>();
            QVERIFY(dasmtest::openMock(*s));
            QSignalSpy spy(s.get(), &SessionObject::snapshotChanged);
            s->diagPublish(4, 5000, false); // threads outlive the object
            QTest::qWait(round % 3);        // sometimes mid-burst, sometimes at once
            s.reset();                      // must not crash or deadlock
            QApplication::processEvents();  // queued closures for the dead object
        }
        QTest::qWait(100);
        QApplication::processEvents();
    }

    // A publication made from inside the notification slot must produce a
    // second notification: `pending` has to be cleared before the emit.
    void publishingFromTheSlotIsNotLost() {
        SessionObject s;
        QVERIFY(dasmtest::openMock(s));
        QApplication::processEvents();
        int calls = 0;
        quint64 lastGeneration = 0;
        QObject::connect(&s, &SessionObject::snapshotChanged, &s, [&](quint64 g) {
            lastGeneration = g;
            if (++calls == 1) QVERIFY(s.rename(0x401010, QStringLiteral("from_slot")).isEmpty());
        });
        s.diagPublish(1, 1, true); // triggers the first notification
        QTRY_VERIFY(calls >= 2);
        QTRY_COMPARE(lastGeneration, s.status().generation); // the last one is current
    }

    void lastRequestedOpenWins() {
        SessionObject s;
        QSignalSpy opened(&s, &SessionObject::opened);
        QSignalSpy errors(&s, &SessionObject::errorOccurred);
        s.diagOpenMockDelayed(400); // slow, requested first
        s.openMock();               // fast, requested last
        QTRY_COMPARE(opened.count(), 1);
        QTest::qWait(700); // the slow one finishes now and must be dropped
        QCOMPARE(opened.count(), 1);
        QVERIFY(s.isOpen());
        // A failing request superseded by a good one reports nothing.
        s.openPath(QStringLiteral("/no/such/file"));
        s.openMock();
        QTRY_COMPARE(opened.count(), 2);
        QTest::qWait(100);
        QCOMPARE(errors.count(), 0);
    }

    void noSessionMeansEmptyAnswers() {
        SessionObject s;
        QVERIFY(!s.isOpen());
        QCOMPARE(s.mappedSize(), quint64(0));
        QVERIFY(s.listingFrom(0, 10).empty());
        QVERIFY(s.functions().empty());
        QCOMPARE(s.diagPublish(2, 10, true), quint64(0));
        QVERIFY(!s.rename(1, QStringLiteral("x")).isEmpty());
        QCOMPARE(s.status().generation, quint64(0));
    }
};

QTEST_MAIN(TestBridge)
#include "test_bridge.moc"
