// 15: the virtualized listing view (keys, scrollbar, wheel, goTo, links).
#include <QScrollBar>
#include <QSignalSpy>
#include <QTest>
#include <QWheelEvent>

#include "ListingView.h"
#include "TestUtil.h"

using dasm::ListingView;

class TestListing : public QObject {
    Q_OBJECT

    std::unique_ptr<dasm::MainWindow> win_;
    ListingView *lv_ = nullptr;
    SessionObject *s_ = nullptr;
    quint64 first_ = 0, lastItem_ = 0;

    void paint() { win_->grab(); } // forces layout and row fetching

    void wheel(int dy) {
        QWheelEvent ev(QPointF(20, 20), QPointF(20, 20), QPoint(), QPoint(0, dy), Qt::NoButton,
                       Qt::NoModifier, Qt::NoScrollPhase, false);
        QApplication::sendEvent(lv_->viewport(), &ev);
    }

private slots:
    void init() {
        win_ = dasmtest::openedWindow();
        QVERIFY(win_);
        lv_ = win_->listing();
        s_ = &win_->session();
        first_ = s_->offsetToAddress(0);
        lastItem_ = s_->listingBefore(UINT64_MAX, 1)[0].addr;
        lv_->setFocus();
        paint();
    }

    void homeAndEnd() {
        QTest::keyClick(lv_, Qt::Key_End);
        paint();
        QCOMPARE(lv_->cursor(), lastItem_);
        QCOMPARE(lv_->rowAddress(lv_->rowCount() - 1), lastItem_);
        QTest::keyClick(lv_, Qt::Key_PageDown); // at the end: stays
        QCOMPARE(lv_->cursor(), lastItem_);
        QTest::keyClick(lv_, Qt::Key_Down);
        QCOMPARE(lv_->cursor(), lastItem_);
        QTest::keyClick(lv_, Qt::Key_Home);
        paint();
        QCOMPARE(lv_->cursor(), first_);
        QCOMPARE(lv_->topAddress(), first_);
        QTest::keyClick(lv_, Qt::Key_PageUp); // at the start: stays
        QCOMPARE(lv_->cursor(), first_);
        QTest::keyClick(lv_, Qt::Key_Up);
        QCOMPARE(lv_->cursor(), first_);
    }

    void pagingMovesByAPageAndBack() {
        QTest::keyClick(lv_, Qt::Key_Home);
        QTest::keyClick(lv_, Qt::Key_PageDown);
        const quint64 down = lv_->cursor();
        QVERIFY(down > first_);
        paint();
        QVERIFY(lv_->rowCount() > 0);
        QTest::keyClick(lv_, Qt::Key_PageUp);
        QCOMPARE(lv_->cursor(), first_);
        // Arrow keys step one item.
        QTest::keyClick(lv_, Qt::Key_Down);
        QCOMPARE(lv_->cursor(), s_->listingFrom(first_, 2)[1].addr);
        QTest::keyClick(lv_, Qt::Key_Up);
        QCOMPARE(lv_->cursor(), first_);
    }

    void scrollbarActions() {
        QScrollBar *sb = lv_->verticalScrollBar();
        QVERIFY(sb->maximum() > 0);
        sb->triggerAction(QAbstractSlider::SliderToMaximum);
        paint();
        QCOMPARE(lv_->rowAddress(lv_->rowCount() - 1), lastItem_);
        QVERIFY(lv_->topAddress() > first_);
        sb->triggerAction(QAbstractSlider::SliderToMinimum);
        paint();
        QCOMPARE(lv_->topAddress(), first_);
        sb->triggerAction(QAbstractSlider::SliderPageStepAdd);
        paint();
        QVERIFY(lv_->topAddress() > first_);
        sb->triggerAction(QAbstractSlider::SliderPageStepSub);
        paint();
        QCOMPARE(lv_->topAddress(), first_);
        sb->triggerAction(QAbstractSlider::SliderSingleStepAdd);
        paint();
        QCOMPARE(lv_->topAddress(), s_->listingFrom(first_, 2)[1].addr);
        sb->triggerAction(QAbstractSlider::SliderSingleStepSub);
        paint();
        QCOMPARE(lv_->topAddress(), first_);
    }

    void sliderMovedAtTheExtremes() {
        QScrollBar *sb = lv_->verticalScrollBar();
        const int max = sb->maximum();
        emit sb->sliderMoved(max); // kScale
        paint();
        QVERIFY(lv_->rowCount() >= 1);
        QCOMPARE(lv_->rowAddress(lv_->rowCount() - 1), lastItem_);
        emit sb->sliderMoved(0);
        paint();
        QCOMPARE(lv_->topAddress(), first_);
        emit sb->sliderMoved(max * 2); // out of range: clamped to the last byte
        paint();
        QCOMPARE(lv_->rowAddress(lv_->rowCount() - 1), lastItem_);
        emit sb->sliderMoved(max); // go to the end first, so "start" is a real change
        paint();
        emit sb->sliderMoved(-5); // negative: treated as the start
        paint();
        QCOMPARE(lv_->topAddress(), first_);
        // A middle position lands strictly inside the mapped bytes.
        emit sb->sliderMoved(max / 2);
        paint();
        QVERIFY(lv_->topAddress() > first_ && lv_->topAddress() <= lastItem_);
    }

    void wheelWithFractionalSteps() {
        const quint64 top0 = lv_->topAddress();
        const quint64 expect = lv_->rowAddress(3);
        wheel(-60); // half a notch: nothing yet
        paint();
        QCOMPARE(lv_->topAddress(), top0);
        wheel(-60); // second half: one notch = 3 rows
        paint();
        QCOMPARE(lv_->topAddress(), expect);
        wheel(120); // a full notch up
        paint();
        QCOMPARE(lv_->topAddress(), top0);
        wheel(30);
        wheel(30);
        wheel(30);
        QCOMPARE(lv_->topAddress(), top0); // 90: still below one notch
        wheel(-240); // 90 up + 240 down leaves 150 = one notch (3 rows), 30 carried
        paint();
        QCOMPARE(lv_->topAddress(), s_->listingFrom(top0, 4)[3].addr);
        // Scrolling up past the start stays at the start.
        wheel(120 * 50);
        paint();
        QCOMPARE(lv_->topAddress(), first_);
    }

    void goToAlignsAndIgnoresUnmapped() {
        lv_->goTo(0x401012); // inside `mov rbp, rsp` (0x401011)
        QCOMPARE(lv_->cursor(), quint64(0x401011));
        lv_->goTo(0x401800); // gap between .text and .rodata
        QCOMPARE(lv_->cursor(), quint64(0x402000));
        const quint64 before = lv_->cursor();
        lv_->goTo(0xdead0000); // nothing at or after it
        QCOMPARE(lv_->cursor(), before);
        lv_->goTo(UINT64_MAX);
        QCOMPARE(lv_->cursor(), before);
        paint();
        QVERIFY(lv_->rowCount() > 0);
        // The target is on screen after a long jump.
        lv_->goTo(first_);
        lv_->goTo(lastItem_);
        paint();
        bool seen = false;
        for (int i = 0; i < lv_->rowCount(); ++i) seen |= lv_->rowAddress(i) == lastItem_;
        QVERIFY(seen);
    }

    void clickOnALinkedTokenRequestsAJump() {
        lv_->goTo(0x401002); // call main
        paint();
        const auto hits = lv_->linkHits();
        QVERIFY(!hits.isEmpty());
        QPair<QRect, quint64> main_hit;
        for (const auto &h : hits) {
            if (h.second == 0x401010) main_hit = h;
        }
        QVERIFY(main_hit.second == 0x401010);
        QSignalSpy spy(lv_, &ListingView::jumpRequested);
        QTest::mouseClick(lv_->viewport(), Qt::LeftButton, {}, main_hit.first.center());
        QVERIFY(spy.count() >= 1);
        QCOMPARE(spy.at(0).at(0).toULongLong(), quint64(0x401010));
    }

    void clickSelectsTheClickedRow() {
        paint();
        QVERIFY(lv_->rowCount() > 6);
        QSignalSpy jump(lv_, &ListingView::jumpRequested);
        QSignalSpy moved(lv_, &ListingView::cursorMoved);
        for (int row : {4, 1, 6, 0}) {
            QTest::mouseClick(lv_->viewport(), Qt::LeftButton, {},
                              QPoint(30, row * lv_->lineHeight() + 2));
            QCOMPARE(lv_->cursor(), lv_->rowAddress(row));
        }
        QCOMPARE(jump.count(), 0); // plain text: no navigation
        QVERIFY(moved.count() >= 3);
        // Below the last row the cursor stays where it was.
        const quint64 c = lv_->cursor();
        QTest::mouseClick(lv_->viewport(), Qt::LeftButton, {},
                          QPoint(30, (lv_->rowCount() + 5) * lv_->lineHeight()));
        QCOMPARE(lv_->cursor(), c);
    }

    void enterFollowsTheFirstLinkedOperand() {
        QSignalSpy spy(lv_, &ListingView::jumpRequested);
        lv_->goTo(0x401000); // xor eax, eax: nothing to follow
        QTest::keyClick(lv_, Qt::Key_Return);
        QCOMPARE(spy.count(), 0);
        lv_->goTo(0x401002); // call main
        paint();
        QTest::keyClick(lv_, Qt::Key_Return);
        QCOMPARE(spy.count(), 1);
        QCOMPARE(spy.at(0).at(0).toULongLong(), quint64(0x401010));
    }
};

QTEST_MAIN(TestListing)
#include "test_listing.moc"
