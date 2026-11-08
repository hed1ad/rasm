#include "MainWindow.h"

#include <QApplication>
#include <QElapsedTimer>
#include <QDragEnterEvent>
#include <QFileInfo>
#include <QLabel>
#include <QListWidget>
#include <QMenuBar>
#include <QMimeData>
#include <QPalette>
#include <QProgressBar>
#include <QStatusBar>
#include <QStyleFactory>
#include <QVBoxLayout>
#include <algorithm>

#include "DockAreaWidget.h"
#include "DockManager.h"
#include "DockWidget.h"
#include "ListPanel.h"
#include "ListingView.h"
#include "Palette.h"

namespace dasm {

// ------------------------------------------------------------ NavHistory

void NavHistory::visit(quint64 addr) {
    if (!entries_.empty() && entries_[index_] == addr) return;
    if (!entries_.empty()) entries_.resize(index_ + 1);
    entries_.push_back(addr);
    index_ = entries_.size() - 1;
}

void NavHistory::updateCurrent(quint64 addr) {
    if (entries_.empty()) {
        entries_.push_back(addr);
        index_ = 0;
    } else {
        entries_[index_] = addr;
    }
}

quint64 NavHistory::back() {
    if (entries_.empty()) return 0;
    if (index_ > 0) --index_;
    return entries_[index_];
}

quint64 NavHistory::forward() {
    if (entries_.empty()) return 0;
    if (index_ + 1 < entries_.size()) ++index_;
    return entries_[index_];
}

void applyTheme() {
    qApp->setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    const Theme &t = theme();
    QPalette p;
    p.setColor(QPalette::Window, QColor(0x2b, 0x2d, 0x31));
    p.setColor(QPalette::WindowText, t.text);
    p.setColor(QPalette::Base, t.background);
    p.setColor(QPalette::AlternateBase, t.altBackground);
    p.setColor(QPalette::Text, t.text);
    p.setColor(QPalette::PlaceholderText, t.dim);
    p.setColor(QPalette::Button, QColor(0x33, 0x35, 0x3a));
    p.setColor(QPalette::ButtonText, t.text);
    p.setColor(QPalette::ToolTipBase, QColor(0x33, 0x35, 0x3a));
    p.setColor(QPalette::ToolTipText, t.text);
    p.setColor(QPalette::Highlight, QColor(0x3d, 0x5a, 0x80));
    p.setColor(QPalette::HighlightedText, Qt::white);
    p.setColor(QPalette::Disabled, QPalette::Text, t.dim);
    p.setColor(QPalette::Disabled, QPalette::ButtonText, t.dim);
    p.setColor(QPalette::Disabled, QPalette::WindowText, t.dim);
    qApp->setPalette(p);
}

// ------------------------------------------------------------ MainWindow

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), session_(), commands_(this) {
    setWindowTitle(QStringLiteral("dasm"));
    resize(1400, 860);
    setAcceptDrops(true);

    ads::CDockManager::setConfigFlag(ads::CDockManager::OpaqueSplitterResize, true);
    ads::CDockManager::setConfigFlag(ads::CDockManager::FocusHighlighting, true);
    docks_ = new ads::CDockManager(this);

    functionsModel_ = new FunctionsModel(this);
    stringsModel_ = new StringsModel(this);
    importsModel_ = new ImportsModel(this);

    buildDocks();
    palette_ = new Palette(&session_, &commands_, functionsModel_, stringsModel_, this);
    connect(palette_, &Palette::navigateTo, this, [this](quint64 a) { navigate(a); });
    connect(palette_, &Palette::openFile, this, [this](const QString &p) { openFile(p); });

    buildCommands();
    buildMenus();

    analysisLabel_ = new QLabel(tr("No file"), this);
    progress_ = new QProgressBar(this);
    progress_->setMaximumWidth(160);
    progress_->setMaximumHeight(14);
    progress_->setTextVisible(false);
    progress_->hide();
    infoLabel_ = new QLabel(this);
    cursorLabel_ = new QLabel(this);
    cursorLabel_->setMinimumWidth(260);
    for (QLabel *l : {analysisLabel_, infoLabel_, cursorLabel_}) l->setTextFormat(Qt::PlainText);
    statusBar()->addWidget(analysisLabel_);
    statusBar()->addWidget(progress_);
    statusBar()->addPermanentWidget(cursorLabel_);
    statusBar()->addPermanentWidget(infoLabel_);

    listsTimer_.setSingleShot(true);
    listsTimer_.setInterval(150);
    connect(&listsTimer_, &QTimer::timeout, this, [this] { refreshListsNow(); });

    connect(&session_, &SessionObject::opened, this, [this] { onOpened(); });
    connect(&session_, &SessionObject::snapshotChanged, this,
            [this](quint64 g) { onSnapshot(g); });
    connect(&session_, &SessionObject::errorOccurred, this, [this](const QString &m) { say(m); });
    connect(listing_, &ListingView::message, this, [this](const QString &m) { say(m); });
    connect(listing_, &ListingView::jumpRequested, this, [this](quint64 a) { navigate(a); });
    connect(listing_, &ListingView::cursorMoved, this, [this](quint64 a) {
        cursorLabel_->setText(QStringLiteral("0x%1  %2").arg(a, 0, 16).arg(session_.nameAt(a)));
        if (!navigating_) nav_.updateCurrent(a);
        updateBreadcrumb();
    });
    updateStatus();
}

MainWindow::~MainWindow() = default;

void MainWindow::buildDocks() {
    auto *container = new QWidget;
    auto *lay = new QVBoxLayout(container);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(0);
    breadcrumb_ = new QLabel(container);
    breadcrumb_->setTextFormat(Qt::PlainText); // names come from the binary
    breadcrumb_->setContentsMargins(8, 3, 8, 3);
    breadcrumb_->setForegroundRole(QPalette::PlaceholderText);
    listing_ = new ListingView(&session_, container);
    lay->addWidget(breadcrumb_);
    lay->addWidget(listing_, 1);

    listingDock_ = new ads::CDockWidget(QStringLiteral("Listing"));
    listingDock_->setWidget(container);
    listingDock_->setFeature(ads::CDockWidget::DockWidgetClosable, false);
    auto *centerArea = docks_->addDockWidget(ads::CenterDockWidgetArea, listingDock_);

    functionsPanel_ = new ListPanel(
        functionsModel_, tr("Functions found by the analysis will appear here."));
    functionsDock_ = new ads::CDockWidget(QStringLiteral("Functions"));
    functionsDock_->setWidget(functionsPanel_);
    auto *leftArea = docks_->addDockWidget(ads::LeftDockWidgetArea, functionsDock_, centerArea);

    stringsPanel_ = new ListPanel(
        stringsModel_, tr("Strings found in the binary will appear here."));
    stringsDock_ = new ads::CDockWidget(QStringLiteral("Strings"));
    stringsDock_->setWidget(stringsPanel_);
    auto *bottomArea = docks_->addDockWidget(ads::BottomDockWidgetArea, stringsDock_, centerArea);

    importsPanel_ = new ListPanel(
        importsModel_, tr("Functions the binary imports from shared libraries will appear here."));
    importsDock_ = new ads::CDockWidget(QStringLiteral("Imports"));
    importsDock_->setWidget(importsPanel_);
    docks_->addDockWidgetTabToArea(importsDock_, bottomArea);

    historyList_ = new QListWidget;
    historyDock_ = new ads::CDockWidget(QStringLiteral("History"));
    historyDock_->setWidget(historyList_);
    docks_->addDockWidgetTabToArea(historyDock_, bottomArea);
    stringsDock_->setAsCurrentTab();

    docks_->setSplitterSizes(leftArea, {300, 1100});
    docks_->setSplitterSizes(centerArea, {560, 240});

    connect(functionsPanel_, &ListPanel::activated, this, [this](quint64 a) { navigate(a); });
    connect(stringsPanel_, &ListPanel::activated, this, [this](quint64 a) { navigate(a); });
    connect(importsPanel_, &ListPanel::activated, this, [this](quint64 a) { navigate(a); });
}

void MainWindow::showDock(ads::CDockWidget *dock) {
    dock->toggleView(true);
    dock->setAsCurrentTab();
    dock->raise();
}

void MainWindow::buildCommands() {
    auto &c = commands_;
    c.add("palette.open", tr("Command palette"), QKeySequence(QStringLiteral("Ctrl+K")), this,
          [this] { palette_->openWith(); });
    c.add("file.open", tr("Open file..."), QKeySequence::Open, this,
          [this] { palette_->openWith(QStringLiteral("open ")); });
    c.add("app.quit", tr("Quit"), QKeySequence::Quit, this, [] { qApp->quit(); });

    auto *undo = c.add("edit.undo", tr("Undo"), QKeySequence::Undo, this, [this] {
        const QString e = session_.undo();
        if (!e.isEmpty()) say(e);
    });
    undo->setEnabled(false);
    auto *redo = c.add("edit.redo", tr("Redo"), QKeySequence(QStringLiteral("Ctrl+Shift+Z")), this,
                       [this] {
                           const QString e = session_.redo();
                           if (!e.isEmpty()) say(e);
                       });
    redo->setEnabled(false);
    c.add("edit.rename", tr("Rename"), QKeySequence(Qt::Key_N), listing_, [this] { listing_->beginRename(); },
          Qt::WidgetShortcut);
    c.add("edit.comment", tr("Add or edit comment"), QKeySequence(Qt::Key_Semicolon), listing_,
          [this] { listing_->beginComment(); }, Qt::WidgetShortcut);

    auto *back = c.add("nav.back", tr("Go back"), QKeySequence(QStringLiteral("Alt+Left")), this, [this] {
        if (!nav_.canBack()) return;
        navigating_ = true;
        listing_->goTo(nav_.back());
        navigating_ = false;
        updateStatus();
    });
    back->setEnabled(false);
    auto *fwd = c.add("nav.forward", tr("Go forward"), QKeySequence(QStringLiteral("Alt+Right")), this,
                      [this] {
                          if (!nav_.canForward()) return;
                          navigating_ = true;
                          listing_->goTo(nav_.forward());
                          navigating_ = false;
                          updateStatus();
                      });
    fwd->setEnabled(false);
    c.add("nav.entry", tr("Go to entry point"), QKeySequence(QStringLiteral("Ctrl+E")), this, [this] {
        const StatusDto st = session_.status();
        if (st.has_entry) navigate(st.entry);
    });
    c.add("nav.goto", tr("Go to address..."), QKeySequence(Qt::Key_G), listing_,
          [this] { palette_->openWith(QStringLiteral("0x")); }, Qt::WidgetShortcut);
    c.add("nav.follow", tr("Follow operand"), QKeySequence(), listing_, [this] { listing_->followCursor(); });

    c.add("view.listing", tr("Show listing"), QKeySequence(QStringLiteral("Ctrl+1")), this, [this] {
        showDock(listingDock_);
        listing_->setFocus();
    });
    c.add("view.functions", tr("Show functions"), QKeySequence(QStringLiteral("Ctrl+2")), this, [this] {
        showDock(functionsDock_);
        functionsPanel_->focusFilter();
    });
    c.add("view.strings", tr("Show strings"), QKeySequence(QStringLiteral("Ctrl+3")), this, [this] {
        showDock(stringsDock_);
        stringsPanel_->focusFilter();
    });
    c.add("view.imports", tr("Show imports"), QKeySequence(QStringLiteral("Ctrl+4")), this, [this] {
        showDock(importsDock_);
        importsPanel_->focusFilter();
    });
    c.add("view.history", tr("Show history"), QKeySequence(QStringLiteral("Ctrl+5")), this,
          [this] { showDock(historyDock_); });

    c.add("start.main", tr("Where is main?"), QKeySequence(), this, [this] {
        const auto &fs = functionsModel_->items();
        for (size_t i = 0; i < fs.size(); ++i) {
            if (qstr(fs[i].name) == QLatin1String("main")) {
                navigate(fs[i].entry);
                return;
            }
        }
        const StatusDto st = session_.status();
        if (st.has_entry) navigate(st.entry);
        say(tr("No function named main; showing the entry point."));
    });
    c.add("start.imports", tr("What does the binary import?"), QKeySequence(), this, [this] {
        showDock(importsDock_);
        importsPanel_->focusFilter();
    });
    c.add("start.strings", tr("Suspicious strings"), QKeySequence(), this, [this] {
        showDock(stringsDock_);
        stringsPanel_->setFilter(QStringLiteral("/"));
        stringsPanel_->focusFilter();
    });
    c.add("help.about", tr("About dasm"), QKeySequence(), this,
          [this] { say(tr("dasm: a Linux-first disassembler. Ctrl+K opens the command palette.")); });
}

void MainWindow::buildMenus() {
    auto addTo = [this](QMenu *m, const char *id) {
        if (const Command *cmd = commands_.find(QString::fromLatin1(id))) m->addAction(cmd->action);
    };
    QMenu *file = menuBar()->addMenu(tr("&File"));
    addTo(file, "file.open");
    file->addSeparator();
    addTo(file, "app.quit");
    QMenu *edit = menuBar()->addMenu(tr("&Edit"));
    for (const char *id : {"edit.undo", "edit.redo", "edit.rename", "edit.comment"}) addTo(edit, id);
    QMenu *go = menuBar()->addMenu(tr("&Go"));
    for (const char *id : {"nav.back", "nav.forward", "nav.entry", "nav.goto", "palette.open"}) addTo(go, id);
    QMenu *view = menuBar()->addMenu(tr("&View"));
    for (const char *id :
         {"view.listing", "view.functions", "view.strings", "view.imports", "view.history"}) addTo(view, id);
    QMenu *help = menuBar()->addMenu(tr("&Help"));
    for (const char *id : {"start.main", "start.imports", "start.strings", "help.about"}) addTo(help, id);
}

void MainWindow::openFile(const QString &path) {
    pendingName_ = QFileInfo(path).fileName();
    statusBar()->showMessage(tr("Opening %1...").arg(path), 3000);
    session_.openPath(path);
}

void MainWindow::openMock() {
    pendingName_ = QStringLiteral("synthetic");
    session_.openMock();
}

void MainWindow::navigate(quint64 addr) {
    if (listing_->hasCursor()) nav_.updateCurrent(listing_->cursor());
    navigating_ = true; // the cursor move below is a new place, not an update
    listing_->goTo(addr);
    navigating_ = false;
    nav_.visit(listing_->cursor());
    updateStatus();
}

void MainWindow::onOpened() {
    nav_ = NavHistory();
    fileName_ = pendingName_;
    importsModel_->reload(session_.imports()); // immutable: loaded once per open
    listing_->reload();
    nav_.visit(listing_->cursor());
    listsGeneration_ = ~quint64{0};
    refreshListsNow();
    updateStatus();
    listing_->setFocus();
}

void MainWindow::onSnapshot(quint64) {
    listing_->invalidate();
    updateStatus();
    if (!listsTimer_.isActive()) listsTimer_.start();
}

void MainWindow::refreshListsNow() {
    listsTimer_.stop();
    if (!session_.isOpen()) return;
    const StatusDto st = session_.status();
    if (st.generation == listsGeneration_) return;
    listsGeneration_ = st.generation;
    QElapsedTimer cost;
    cost.start();
    // Unchanged tables are left alone, appended rows are inserted, and only a
    // real change resets (keeping selection and scroll, see ListPanel).
    functionsModel_->reload(session_.functions());
    stringsModel_->reload(session_.strings());
    historyList_->clear();
    const auto hist = session_.history();
    for (size_t i = hist.size(); i-- > 0;) {
        auto *item = new QListWidgetItem(
            QStringLiteral("#%1  %2").arg(hist[i].seq).arg(qstr(hist[i].text)), historyList_);
        if (hist[i].undone) {
            QFont f = item->font();
            f.setStrikeOut(true);
            item->setFont(f);
            item->setForeground(theme().dim);
        }
    }
    // Back off in proportion to the cost so that refreshing never takes more
    // than about a tenth of the UI thread, however large the binary is.
    listsTimer_.setInterval(std::clamp(static_cast<int>(cost.elapsed() * 10), 150, 5000));
}

void MainWindow::updateStatus() {
    if (!session_.isOpen()) {
        analysisLabel_->setText(tr("No file"));
        return;
    }
    const StatusDto st = session_.status();
    switch (st.analysis_state) {
    case 1:
        analysisLabel_->setText(tr("Analysing: %1 (%2/%3)")
                                    .arg(qstr(st.current_pass))
                                    .arg(st.done)
                                    .arg(st.total));
        progress_->setRange(0, static_cast<int>(std::min<quint64>(st.total, 1'000'000'000)));
        progress_->setValue(static_cast<int>(std::min<quint64>(st.done, 1'000'000'000)));
        progress_->show();
        break;
    case 2: analysisLabel_->setText(tr("Analysis complete")); progress_->hide(); break;
    case 3: analysisLabel_->setText(tr("Analysis cancelled")); progress_->hide(); break;
    case 4: {
        const QString err = qstr(st.error);
        analysisLabel_->setText(err.isEmpty() ? tr("Analysis failed")
                                              : tr("Analysis failed: %1").arg(err));
        progress_->hide();
        break;
    }
    default: analysisLabel_->setText(tr("Idle")); progress_->hide(); break;
    }
    infoLabel_->setText(QStringLiteral("%1  |  %2 functions  |  snapshot %3")
                            .arg(qstr(st.file_info))
                            .arg(st.function_count)
                            .arg(st.generation));
    if (auto *u = commands_.find(QStringLiteral("edit.undo"))) u->action->setEnabled(st.can_undo);
    if (auto *r = commands_.find(QStringLiteral("edit.redo"))) r->action->setEnabled(st.can_redo);
    if (auto *b = commands_.find(QStringLiteral("nav.back"))) b->action->setEnabled(nav_.canBack());
    if (auto *f = commands_.find(QStringLiteral("nav.forward"))) f->action->setEnabled(nav_.canForward());
}

void MainWindow::updateBreadcrumb() {
    if (!listing_->hasCursor()) return;
    breadcrumb_->setText(fileName_ + QStringLiteral(" › ") + session_.breadcrumb(listing_->cursor()));
}

void MainWindow::say(const QString &text) { statusBar()->showMessage(text, 8000); }

void MainWindow::dragEnterEvent(QDragEnterEvent *e) {
    if (e->mimeData()->hasUrls()) e->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent *e) {
    for (const QUrl &u : e->mimeData()->urls()) {
        if (u.isLocalFile()) {
            openFile(u.toLocalFile());
            return;
        }
    }
}

} // namespace dasm
