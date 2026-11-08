// 11, 12: table models (QAbstractItemModelTester, sorting) and ListPanel.
#include <QAbstractItemModelTester>
#include <QElapsedTimer>
#include <QLineEdit>
#include <QScrollBar>
#include <QSignalSpy>
#include <QSortFilterProxyModel>
#include <QTest>
#include <QTreeView>

#include "ListPanel.h"
#include "TestUtil.h"

using namespace dasm;

namespace {

rust::Vec<FuncDto> funcs(std::initializer_list<std::pair<const char *, quint64>> items) {
    rust::Vec<FuncDto> v;
    quint32 n = 0;
    for (const auto &[name, entry] : items) {
        FuncDto f{};
        f.entry = entry;
        f.name = rust::String(name);
        f.size = entry % 97;
        f.blocks = n % 5;
        f.insns = 100 - n;
        f.flags = n % 3 == 0 ? 0b10 : 0;
        v.push_back(f);
        ++n;
    }
    return v;
}

int cmp(const QVariant &a, const QVariant &b) {
    if (a.typeId() == QMetaType::QString) return a.toString().compare(b.toString());
    const qulonglong x = a.toULongLong(), y = b.toULongLong();
    return x < y ? -1 : (x > y ? 1 : 0);
}

// Sorts by every column in both directions under a model tester and checks
// that SortRole values are ordered.
void checkSorting(QAbstractItemModel &model) {
    QSortFilterProxyModel proxy;
    proxy.setSourceModel(&model);
    proxy.setSortRole(SortRole);
    QAbstractItemModelTester tester(&proxy, QAbstractItemModelTester::FailureReportingMode::QtTest);
    for (int col = 0; col < model.columnCount(); ++col) {
        for (Qt::SortOrder order : {Qt::AscendingOrder, Qt::DescendingOrder}) {
            proxy.sort(col, order);
            for (int r = 1; r < proxy.rowCount(); ++r) {
                const int c = cmp(proxy.index(r - 1, col).data(SortRole),
                                  proxy.index(r, col).data(SortRole));
                QVERIFY2(order == Qt::AscendingOrder ? c <= 0 : c >= 0,
                         qPrintable(QStringLiteral("column %1 row %2").arg(col).arg(r)));
            }
        }
    }
}

} // namespace

class TestModels : public QObject {
    Q_OBJECT
    SessionObject session_;

private slots:
    void initTestCase() { QVERIFY(dasmtest::openMock(session_)); }

    void functionsModel() {
        FunctionsModel m;
        QAbstractItemModelTester t(&m, QAbstractItemModelTester::FailureReportingMode::QtTest);
        QCOMPARE(m.rowCount(), 0);
        m.reload(session_.functions());
        QVERIFY(m.rowCount() >= 3);
        QCOMPARE(m.columnCount(), 5);
        checkSorting(m);
        m.reload(funcs({{"zeta", 0x3000},
                        {"alpha", 0},
                        {"\xc3\xa9t\xc3\xa9", 0x10},
                        {"Beta", UINT64_MAX},
                        {"alpha", 0x2000}}));
        QCOMPARE(m.rowCount(), 5);
        checkSorting(m);
        QCOMPARE(m.index(3, 0).data(AddressRole).toULongLong(), quint64(UINT64_MAX));
        m.reload(rust::Vec<FuncDto>());
        QCOMPARE(m.rowCount(), 0);
        checkSorting(m);
    }

    void stringsModel() {
        StringsModel m;
        QAbstractItemModelTester t(&m, QAbstractItemModelTester::FailureReportingMode::QtTest);
        m.reload(rust::Vec<StringDto>());
        QCOMPARE(m.rowCount(), 0);
        m.reload(session_.strings());
        QVERIFY(m.rowCount() >= 2);
        QCOMPARE(m.columnCount(), 4);
        checkSorting(m);
        m.reload(rust::Vec<StringDto>());
        QCOMPARE(m.rowCount(), 0);
    }

    void importsModel() {
        ImportsModel m;
        QAbstractItemModelTester t(&m, QAbstractItemModelTester::FailureReportingMode::QtTest);
        m.reload(rust::Vec<ImportDto>());
        QCOMPARE(m.rowCount(), 0);
        m.reload(session_.imports());
        QVERIFY(m.rowCount() >= 1);
        QCOMPARE(m.columnCount(), 4);
        checkSorting(m);
        // An import with neither PLT nor GOT has no address to jump to.
        rust::Vec<ImportDto> v;
        ImportDto i{};
        i.name = rust::String("orphan");
        v.push_back(i);
        m.reload(std::move(v));
        QCOMPARE(m.index(0, 0).data(AddressRole).toULongLong(), quint64(0));
        QCOMPARE(m.index(0, 3).data(Qt::DisplayRole).toString(), QString());
    }

    // Sorting as the user gets it: through the panel's own proxy, with data
    // where numeric and lexicographic order differ (0x9 < 0x10 < 0x100).
    void panelSortsNumericallyNotAsText() {
        FunctionsModel m;
        m.reload(funcs({{"b", 0x10}, {"A", 0x9}, {"c", 0x100}, {"B", 0x2}}));
        ListPanel panel(&m, QStringLiteral("empty"));
        panel.show();
        const auto column = [&](int col, int role) {
            QStringList out;
            for (int r = 0; r < panel.proxy()->rowCount(); ++r) {
                out << panel.proxy()->index(r, col).data(role).toString();
            }
            return out;
        };
        panel.view()->sortByColumn(1, Qt::AscendingOrder); // Address
        QCOMPARE(column(1, Qt::DisplayRole), (QStringList{"0x2", "0x9", "0x10", "0x100"}));
        panel.view()->sortByColumn(1, Qt::DescendingOrder);
        QCOMPARE(column(1, Qt::DisplayRole), (QStringList{"0x100", "0x10", "0x9", "0x2"}));
        panel.view()->sortByColumn(0, Qt::AscendingOrder); // Name: case-insensitive
        const QStringList names = column(0, Qt::DisplayRole);
        QCOMPARE(names.at(0), QStringLiteral("A"));
        QCOMPARE(names.at(3), QStringLiteral("c"));
        QCOMPARE(names.at(1).toLower(), QStringLiteral("b"));
        QCOMPARE(names.at(2).toLower(), QStringLiteral("b"));
        panel.view()->sortByColumn(2, Qt::AscendingOrder); // Size = entry % 97
        QCOMPARE(column(2, Qt::DisplayRole), (QStringList{"2", "9", "16", "62"}));
    }

    void stringsAndImportsSortNumerically() {
        StringsModel sm;
        rust::Vec<StringDto> sv;
        for (quint64 len : {9, 100, 10}) {
            StringDto d{};
            d.addr = len * 7;
            d.byte_len = len;
            d.value = rust::String("v");
            sv.push_back(d);
        }
        sm.reload(std::move(sv));
        ListPanel sp(&sm, QStringLiteral("empty"));
        sp.view()->sortByColumn(2, Qt::AscendingOrder); // Bytes
        QCOMPARE(sp.proxy()->index(0, 2).data().toString(), QStringLiteral("9"));
        QCOMPARE(sp.proxy()->index(1, 2).data().toString(), QStringLiteral("10"));
        QCOMPARE(sp.proxy()->index(2, 2).data().toString(), QStringLiteral("100"));
        sp.view()->sortByColumn(0, Qt::AscendingOrder); // Address 63, 70, 700
        QCOMPARE(sp.proxy()->index(0, 0).data().toString(), QStringLiteral("0x3f"));
        QCOMPARE(sp.proxy()->index(2, 0).data().toString(), QStringLiteral("0x2bc"));
    }

    // ---- refresh without losing the user's place

    void identicalReloadChangesNothing() {
        FunctionsModel m;
        m.reload(funcs({{"a", 1}, {"b", 2}}));
        QSignalSpy reset(&m, &QAbstractItemModel::modelReset);
        QSignalSpy inserted(&m, &QAbstractItemModel::rowsInserted);
        QVERIFY(!m.reload(funcs({{"a", 1}, {"b", 2}})));
        QCOMPARE(reset.count(), 0);
        QCOMPARE(inserted.count(), 0);
        QVERIFY(m.reload(funcs({{"a", 1}, {"b", 3}}))); // one field differs
        QCOMPARE(reset.count(), 1);
    }

    void appendInsertsRowsAndKeepsSelection() {
        FunctionsModel m;
        m.reload(funcs({{"a", 1}, {"b", 2}, {"c", 3}}));
        ListPanel panel(&m, QStringLiteral("empty"));
        panel.show();
        panel.view()->setCurrentIndex(panel.proxy()->index(1, 0));
        QSignalSpy reset(&m, &QAbstractItemModel::modelReset);
        QSignalSpy inserted(&m, &QAbstractItemModel::rowsInserted);
        QVERIFY(m.reload(funcs({{"a", 1}, {"b", 2}, {"c", 3}, {"d", 4}, {"e", 5}})));
        QCOMPARE(reset.count(), 0);
        QCOMPARE(inserted.count(), 1);
        QCOMPARE(m.rowCount(), 5);
        QCOMPARE(panel.view()->currentIndex().data(AddressRole).toULongLong(), quint64(2));
    }

    void resetKeepsSelectionAndScrollPosition() {
        std::vector<std::pair<std::string, quint64>> names;
        for (quint64 i = 0; i < 2000; ++i) names.emplace_back("fn_" + std::to_string(i), 0x1000 + i);
        auto build = [&](quint64 changedLast) {
            rust::Vec<FuncDto> v;
            for (size_t i = 0; i < names.size(); ++i) {
                FuncDto f{};
                f.entry = names[i].second;
                f.name = rust::String(names[i].first);
                f.size = i == names.size() - 1 ? changedLast : 1;
                v.push_back(f);
            }
            return v;
        };
        FunctionsModel m;
        m.reload(build(1));
        ListPanel panel(&m, QStringLiteral("empty"));
        panel.resize(400, 200);
        panel.show();
        QVERIFY(QTest::qWaitForWindowExposed(&panel));
        panel.view()->sortByColumn(1, Qt::AscendingOrder);
        const QModelIndex sel = panel.proxy()->index(1200, 0);
        panel.view()->setCurrentIndex(sel);
        panel.view()->scrollTo(sel, QAbstractItemView::PositionAtTop);
        QApplication::processEvents();
        const int scroll = panel.view()->verticalScrollBar()->value();
        QVERIFY(scroll > 0);
        QSignalSpy reset(&m, &QAbstractItemModel::modelReset);
        QVERIFY(m.reload(build(2))); // real change: a full reset
        QCOMPARE(reset.count(), 1);
        QTRY_COMPARE(panel.view()->currentIndex().data(AddressRole).toULongLong(),
                     quint64(0x1000 + 1200));
        QTRY_COMPARE(panel.view()->verticalScrollBar()->value(), scroll);
    }

    void largeTablesAreCheapToRefresh() {
        auto build = [](quint32 salt) {
            rust::Vec<FuncDto> v;
            for (quint64 i = 0; i < 20000; ++i) {
                FuncDto f{};
                f.entry = 0x1000 + i * 16;
                f.name = rust::String("function_" + std::to_string(i));
                f.size = 16 + salt;
                v.push_back(f);
            }
            return v;
        };
        FunctionsModel m;
        m.reload(build(0));
        ListPanel panel(&m, QStringLiteral("empty"));
        panel.show();
        QElapsedTimer t;
        t.start();
        QVERIFY(!m.reload(build(0))); // the common case during analysis: nothing new
        QVERIFY2(t.elapsed() < 250, qPrintable(QString::number(t.elapsed())));
        t.restart();
        QVERIFY(m.reload(build(1)));
        qInfo() << "full reset of 20000 functions with sorting:" << t.elapsed() << "ms";
    }

    void panelFilterWithoutMatches() {
        FunctionsModel m;
        m.reload(session_.functions());
        ListPanel panel(&m, QStringLiteral("empty"));
        panel.show();
        QVERIFY(panel.view()->isVisibleTo(&panel));
        const int total = panel.sourceRows();
        panel.setFilter(QStringLiteral("zzzzzzzz-no-such-function"));
        QCOMPARE(panel.visibleRows(), 0);
        QCOMPARE(panel.sourceRows(), total);
        QVERIFY(panel.view()->isVisibleTo(&panel)); // empty table, not the empty-state text
        panel.setFilter(QString());
        QCOMPARE(panel.visibleRows(), total);
        // Case-insensitive substring over all columns (address column too).
        panel.setFilter(QStringLiteral("MAIN"));
        QVERIFY(panel.visibleRows() >= 1);
        panel.setFilter(QStringLiteral("0x401010"));
        QVERIFY(panel.visibleRows() >= 1);
    }

    void panelEmptyStateAppearsAndDisappears() {
        FunctionsModel m;
        ListPanel panel(&m, QStringLiteral("nothing yet"));
        panel.show();
        QVERIFY(!panel.view()->isVisibleTo(&panel));
        m.reload(session_.functions());
        QVERIFY(panel.view()->isVisibleTo(&panel));
        m.reload(rust::Vec<FuncDto>());
        QVERIFY(!panel.view()->isVisibleTo(&panel));
    }

    void enterInTheFilterSelectsTheFirstRow() {
        FunctionsModel m;
        m.reload(session_.functions());
        ListPanel panel(&m, QStringLiteral("empty"));
        panel.show();
        panel.setFilter(QStringLiteral("main"));
        QVERIFY(!panel.view()->currentIndex().isValid());
        auto *edit = panel.findChild<QLineEdit *>();
        QVERIFY(edit);
        QTest::keyClick(edit, Qt::Key_Return);
        QVERIFY(panel.view()->currentIndex().isValid());
        QCOMPARE(panel.view()->currentIndex().row(), 0);
        QCOMPARE(panel.view()->currentIndex().data(Qt::DisplayRole).toString(),
                 QStringLiteral("main"));
    }

    void activatedIsNotEmittedForAddressZero() {
        FunctionsModel m;
        m.reload(funcs({{"at_zero", 0}}));
        ListPanel panel(&m, QStringLiteral("empty"));
        panel.show();
        QSignalSpy spy(&panel, &ListPanel::activated);
        const QModelIndex idx = panel.proxy()->index(0, 0);
        emit panel.view()->activated(idx);
        emit panel.view()->doubleClicked(idx);
        QCOMPARE(spy.count(), 0);

        m.reload(funcs({{"real", 0x1234}}));
        emit panel.view()->activated(panel.proxy()->index(0, 0));
        QCOMPARE(spy.count(), 1);
        QCOMPARE(spy.at(0).at(0).toULongLong(), quint64(0x1234));
        emit panel.view()->doubleClicked(panel.proxy()->index(0, 0));
        QCOMPARE(spy.count(), 2);
        emit panel.view()->activated(QModelIndex()); // invalid index: ignored
        QCOMPARE(spy.count(), 2);
    }
};

QTEST_MAIN(TestModels)
#include "test_models.moc"
