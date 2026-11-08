#pragma once
// Functions / strings / imports tables: a QAbstractTableModel over the
// bridge's plain records, a QSortFilterProxyModel for filter and sorting.

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QWidget>

#include "Common.h"

class QLabel;
class QLineEdit;
class QTreeView;

namespace dasm {

enum ListRole { AddressRole = Qt::UserRole + 1, SortRole };

inline bool same(const FuncDto &a, const FuncDto &b) {
    return a.entry == b.entry && a.size == b.size && a.blocks == b.blocks &&
           a.insns == b.insns && a.flags == b.flags && a.name == b.name;
}
inline bool same(const StringDto &a, const StringDto &b) {
    return a.addr == b.addr && a.byte_len == b.byte_len && a.value == b.value &&
           a.encoding == b.encoding;
}
inline bool same(const ImportDto &a, const ImportDto &b) {
    return a.has_plt == b.has_plt && a.plt == b.plt && a.got == b.got && a.name == b.name &&
           a.library == b.library && a.version == b.version;
}

enum class Change { None, Append, Other };

// How `next` differs from `old`: identical, `old` plus new rows at the end,
// or something else.
template <class Vec> Change classify(const Vec &old, const Vec &next) {
    size_t common = 0;
    while (common < old.size() && common < next.size() && same(old[common], next[common])) ++common;
    if (common < old.size()) return Change::Other;
    return next.size() == old.size() ? Change::None : Change::Append;
}

// Base of the table models: applies a new data set with the cheapest signal
// sequence (nothing, rows inserted, or a full reset).
class TableBase : public QAbstractTableModel {
public:
    using QAbstractTableModel::QAbstractTableModel;

protected:
    template <class Vec, class After> bool applyVec(Vec &items, Vec next, After after) {
        const Change c = classify(items, next);
        if (c == Change::None) return false;
        if (c == Change::Append) {
            beginInsertRows({}, static_cast<int>(items.size()), static_cast<int>(next.size()) - 1);
            items = std::move(next);
            after();
            endInsertRows();
        } else {
            beginResetModel();
            items = std::move(next);
            after();
            endResetModel();
        }
        return true;
    }
};

class FunctionsModel : public TableBase {
    Q_OBJECT
public:
    using TableBase::TableBase;
    // Returns false when nothing changed. Unchanged data is a no-op, a pure
    // append inserts rows (selection and scroll survive), anything else resets.
    bool reload(rust::Vec<FuncDto> items);
    const rust::Vec<FuncDto> &items() const { return items_; }
    int rowCount(const QModelIndex &p = {}) const override { return p.isValid() ? 0 : static_cast<int>(items_.size()); }
    int columnCount(const QModelIndex &p = {}) const override { return p.isValid() ? 0 : 5; }
    QVariant data(const QModelIndex &, int role) const override;
    QVariant headerData(int, Qt::Orientation, int role) const override;

private:
    rust::Vec<FuncDto> items_;
    QStringList lowerNames_; // sort keys, so sorting does not lower-case per compare
};

class StringsModel : public TableBase {
    Q_OBJECT
public:
    using TableBase::TableBase;
    bool reload(rust::Vec<StringDto> items);
    const rust::Vec<StringDto> &items() const { return items_; }
    int rowCount(const QModelIndex &p = {}) const override { return p.isValid() ? 0 : static_cast<int>(items_.size()); }
    int columnCount(const QModelIndex &p = {}) const override { return p.isValid() ? 0 : 4; }
    QVariant data(const QModelIndex &, int role) const override;
    QVariant headerData(int, Qt::Orientation, int role) const override;

private:
    rust::Vec<StringDto> items_;
};

class ImportsModel : public TableBase {
    Q_OBJECT
public:
    using TableBase::TableBase;
    bool reload(rust::Vec<ImportDto> items);
    int rowCount(const QModelIndex &p = {}) const override { return p.isValid() ? 0 : static_cast<int>(items_.size()); }
    int columnCount(const QModelIndex &p = {}) const override { return p.isValid() ? 0 : 4; }
    QVariant data(const QModelIndex &, int role) const override;
    QVariant headerData(int, Qt::Orientation, int role) const override;

private:
    rust::Vec<ImportDto> items_;
};

// Filter line + table + an empty-state explanation.
class ListPanel : public QWidget {
    Q_OBJECT
public:
    ListPanel(QAbstractTableModel *model, const QString &emptyText, QWidget *parent = nullptr);
    void setFilter(const QString &text);
    void focusFilter();
    int visibleRows() const;
    int sourceRows() const;
    QSortFilterProxyModel *proxy() const { return proxy_; }
    QTreeView *view() const { return view_; }

signals:
    // Enter / double click on a row with an address.
    void activated(quint64 addr);

private:
    QAbstractTableModel *model_;
    QSortFilterProxyModel *proxy_;
    QLineEdit *filter_;
    QTreeView *view_;
    QLabel *empty_;
    int rowsBeforeReset_ = 0;
    QVariant selectedBeforeReset_;
    int scrollBeforeReset_ = 0;
    void updateEmpty();
};

} // namespace dasm
