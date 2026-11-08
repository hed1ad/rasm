#include "ListPanel.h"

#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QScrollBar>
#include <QTimer>
#include <QTreeView>
#include <QVBoxLayout>

namespace dasm {

namespace {
QString hex(quint64 v) { return QStringLiteral("0x%1").arg(v, 0, 16); }

} // namespace

// ------------------------------------------------------------ functions

bool FunctionsModel::reload(rust::Vec<FuncDto> items) {
    return applyVec(items_, std::move(items), [this] {
        lowerNames_.clear();
        lowerNames_.reserve(static_cast<qsizetype>(items_.size()));
        for (const FuncDto &f : items_) lowerNames_.append(qstr(f.name).toLower());
    });
}

QVariant FunctionsModel::data(const QModelIndex &idx, int role) const {
    if (!idx.isValid() || static_cast<size_t>(idx.row()) >= items_.size()) return {};
    const FuncDto &f = items_[static_cast<size_t>(idx.row())];
    if (role == AddressRole) return QVariant::fromValue<quint64>(f.entry);
    if (role == SortRole) {
        switch (idx.column()) {
        case 0: return lowerNames_.at(idx.row());
        case 1: return QVariant::fromValue<quint64>(f.entry);
        case 2: return QVariant::fromValue<quint64>(f.size);
        case 3: return f.blocks;
        default: return f.insns;
        }
    }
    if (role == Qt::DisplayRole) {
        switch (idx.column()) {
        case 0: return qstr(f.name);
        case 1: return hex(f.entry);
        case 2: return QVariant::fromValue<quint64>(f.size);
        case 3: return f.blocks;
        default: return f.insns;
        }
    }
    if (role == Qt::ForegroundRole && (f.flags & 0b110) != 0) return theme().dim;
    if (role == Qt::TextAlignmentRole && idx.column() >= 2) return int(Qt::AlignRight | Qt::AlignVCenter);
    return {};
}

QVariant FunctionsModel::headerData(int s, Qt::Orientation o, int role) const {
    static const char *names[] = {"Name", "Address", "Size", "Blocks", "Insns"};
    if (o == Qt::Horizontal && role == Qt::DisplayRole && s >= 0 && s < 5) return tr(names[s]);
    return {};
}

// -------------------------------------------------------------- strings

bool StringsModel::reload(rust::Vec<StringDto> items) {
    return applyVec(items_, std::move(items), [] {});
}

QVariant StringsModel::data(const QModelIndex &idx, int role) const {
    if (!idx.isValid() || static_cast<size_t>(idx.row()) >= items_.size()) return {};
    const StringDto &s = items_[static_cast<size_t>(idx.row())];
    if (role == AddressRole) return QVariant::fromValue<quint64>(s.addr);
    if (role == SortRole) {
        switch (idx.column()) {
        case 0: return QVariant::fromValue<quint64>(s.addr);
        case 1: return qstr(s.value);
        case 2: return QVariant::fromValue<quint64>(s.byte_len);
        default: return qstr(s.encoding);
        }
    }
    if (role == Qt::DisplayRole) {
        switch (idx.column()) {
        case 0: return hex(s.addr);
        case 1: return qstr(s.value);
        case 2: return QVariant::fromValue<quint64>(s.byte_len);
        default: return qstr(s.encoding);
        }
    }
    if (role == Qt::ForegroundRole && idx.column() == 1) return theme().token(String);
    return {};
}

QVariant StringsModel::headerData(int s, Qt::Orientation o, int role) const {
    static const char *names[] = {"Address", "String", "Bytes", "Encoding"};
    if (o == Qt::Horizontal && role == Qt::DisplayRole && s >= 0 && s < 4) return tr(names[s]);
    return {};
}

// -------------------------------------------------------------- imports

bool ImportsModel::reload(rust::Vec<ImportDto> items) {
    return applyVec(items_, std::move(items), [] {});
}

QVariant ImportsModel::data(const QModelIndex &idx, int role) const {
    if (!idx.isValid() || static_cast<size_t>(idx.row()) >= items_.size()) return {};
    const ImportDto &i = items_[static_cast<size_t>(idx.row())];
    if (role == AddressRole) {
        return QVariant::fromValue<quint64>(i.has_plt ? i.plt : i.got);
    }
    if (role == SortRole || role == Qt::DisplayRole) {
        switch (idx.column()) {
        case 0: return qstr(i.name);
        case 1: return qstr(i.library);
        case 2: return qstr(i.version);
        default:
            if (role == SortRole) return QVariant::fromValue<quint64>(i.has_plt ? i.plt : i.got);
            return i.has_plt ? hex(i.plt) : (i.got ? hex(i.got) : QString());
        }
    }
    return {};
}

QVariant ImportsModel::headerData(int s, Qt::Orientation o, int role) const {
    static const char *names[] = {"Name", "Library", "Version", "PLT"};
    if (o == Qt::Horizontal && role == Qt::DisplayRole && s >= 0 && s < 4) return tr(names[s]);
    return {};
}

// ---------------------------------------------------------------- panel

ListPanel::ListPanel(QAbstractTableModel *model, const QString &emptyText, QWidget *parent)
    : QWidget(parent), model_(model) {
    proxy_ = new QSortFilterProxyModel(this);
    proxy_->setSourceModel(model);
    proxy_->setSortRole(SortRole);
    proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_->setFilterKeyColumn(-1);

    filter_ = new QLineEdit(this);
    filter_->setPlaceholderText(tr("Filter..."));
    filter_->setClearButtonEnabled(true);

    view_ = new QTreeView(this);
    view_->setModel(proxy_);
    view_->setRootIsDecorated(false);
    view_->setUniformRowHeights(true);
    view_->setSortingEnabled(true);
    view_->setAlternatingRowColors(true);
    view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    view_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    view_->header()->setStretchLastSection(true);
    view_->header()->setSectionResizeMode(QHeaderView::Interactive);

    empty_ = new QLabel(emptyText, this);
    empty_->setTextFormat(Qt::PlainText);
    empty_->setWordWrap(true);
    empty_->setAlignment(Qt::AlignCenter);
    empty_->setForegroundRole(QPalette::PlaceholderText);

    auto *lay = new QVBoxLayout(this);
    lay->setContentsMargins(2, 2, 2, 2);
    lay->setSpacing(2);
    lay->addWidget(filter_);
    lay->addWidget(view_, 1);
    lay->addWidget(empty_, 1);

    connect(filter_, &QLineEdit::textChanged, this, [this](const QString &t) {
        proxy_->setFilterFixedString(t);
        updateEmpty();
    });
    connect(filter_, &QLineEdit::returnPressed, this, [this] {
        if (proxy_->rowCount() > 0 && !view_->currentIndex().isValid()) {
            view_->setCurrentIndex(proxy_->index(0, 0));
        }
        view_->setFocus();
    });
    auto activate = [this](const QModelIndex &i) {
        if (!i.isValid()) return;
        const quint64 a = i.data(AddressRole).toULongLong();
        if (a != 0) emit activated(a);
    };
    connect(view_, &QTreeView::activated, this, activate);
    connect(view_, &QTreeView::doubleClicked, this, activate);
    // A reset (data really changed) must not lose what the user was doing:
    // remember the selected address and the scroll position, restore after.
    connect(model, &QAbstractItemModel::modelAboutToBeReset, this, [this] {
        rowsBeforeReset_ = model_->rowCount();
        const QModelIndex cur = view_->currentIndex();
        selectedBeforeReset_ = cur.isValid() ? cur.data(AddressRole) : QVariant();
        scrollBeforeReset_ = view_->verticalScrollBar()->value();
    });
    connect(model, &QAbstractItemModel::modelReset, this, [this] {
        updateEmpty();
        if (rowsBeforeReset_ == 0) {
            // First fill: size the first column once (measuring every row on
            // each later reset would cost far more than the reset itself).
            view_->resizeColumnToContents(0);
            return;
        }
        const QVariant sel = selectedBeforeReset_;
        const int scroll = scrollBeforeReset_;
        QTimer::singleShot(0, this, [this, sel, scroll] {
            if (sel.isValid()) {
                for (int r = 0; r < proxy_->rowCount(); ++r) {
                    const QModelIndex i = proxy_->index(r, 0);
                    if (i.data(AddressRole) == sel) {
                        view_->setCurrentIndex(i);
                        break;
                    }
                }
            }
            view_->verticalScrollBar()->setValue(scroll);
        });
    });
    connect(model, &QAbstractItemModel::rowsInserted, this, [this] { updateEmpty(); });
    updateEmpty();
}

void ListPanel::updateEmpty() {
    const bool none = model_->rowCount() == 0;
    empty_->setVisible(none);
    view_->setVisible(!none);
    if (!none && proxy_->rowCount() == 0) {
        // Filter excludes everything: keep the (empty) table visible.
        view_->setVisible(true);
    }
}

void ListPanel::setFilter(const QString &text) { filter_->setText(text); }
void ListPanel::focusFilter() {
    filter_->setFocus();
    filter_->selectAll();
}
int ListPanel::visibleRows() const { return proxy_->rowCount(); }
int ListPanel::sourceRows() const { return model_->rowCount(); }

} // namespace dasm
