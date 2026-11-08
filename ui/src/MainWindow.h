#pragma once

#include <QMainWindow>
#include <QTimer>
#include <vector>

#include "Commands.h"
#include "Common.h"

class QLabel;
class QListWidget;
class QProgressBar;

namespace ads {
class CDockManager;
class CDockWidget;
} // namespace ads

namespace dasm {

class FunctionsModel;
class ImportsModel;
class ListPanel;
class ListingView;
class Palette;
class StringsModel;

// Back/forward list of visited places (Alt+Left / Alt+Right).
class NavHistory {
public:
    // Remembers `addr` as the current place, dropping the forward tail.
    void visit(quint64 addr);
    // Updates the current entry without creating a new one.
    void updateCurrent(quint64 addr);
    bool canBack() const { return index_ > 0; }
    bool canForward() const { return index_ + 1 < entries_.size(); }
    quint64 back();
    quint64 forward();
    size_t size() const { return entries_.size(); }

private:
    std::vector<quint64> entries_;
    size_t index_ = 0;
};

void applyTheme();

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

    SessionObject &session() { return session_; }
    CommandRegistry &commands() { return commands_; }
    ListingView *listing() { return listing_; }
    Palette *palette() { return palette_; }
    ListPanel *functionsPanel() { return functionsPanel_; }
    ListPanel *stringsPanel() { return stringsPanel_; }
    ListPanel *importsPanel() { return importsPanel_; }
    NavHistory &nav() { return nav_; }
    QListWidget *historyList() { return historyList_; }

    void openFile(const QString &path);
    void openMock();
    // Records the current place in history, then goes to `addr`.
    void navigate(quint64 addr);
    // Re-reads the tables now instead of after the throttle delay.
    void refreshListsNow();
    void updateStatus();
    int listsInterval() const { return listsTimer_.interval(); }

protected:
    void dragEnterEvent(QDragEnterEvent *) override;
    void dropEvent(QDropEvent *) override;

private:
    void buildCommands();
    void buildDocks();
    void buildMenus();
    void showDock(ads::CDockWidget *dock);
    void onOpened();
    void onSnapshot(quint64 generation);
    void say(const QString &text);
    void updateBreadcrumb();

    SessionObject session_;
    CommandRegistry commands_;
    NavHistory nav_;
    QString fileName_;    // of the open session
    QString pendingName_; // of the latest open request

    ads::CDockManager *docks_ = nullptr;
    ads::CDockWidget *functionsDock_ = nullptr;
    ads::CDockWidget *stringsDock_ = nullptr;
    ads::CDockWidget *importsDock_ = nullptr;
    ads::CDockWidget *historyDock_ = nullptr;
    ads::CDockWidget *listingDock_ = nullptr;

    ListingView *listing_ = nullptr;
    QLabel *breadcrumb_ = nullptr;
    FunctionsModel *functionsModel_ = nullptr;
    StringsModel *stringsModel_ = nullptr;
    ImportsModel *importsModel_ = nullptr;
    ListPanel *functionsPanel_ = nullptr;
    ListPanel *stringsPanel_ = nullptr;
    ListPanel *importsPanel_ = nullptr;
    QListWidget *historyList_ = nullptr;
    Palette *palette_ = nullptr;

    QLabel *analysisLabel_ = nullptr;
    QProgressBar *progress_ = nullptr;
    QLabel *infoLabel_ = nullptr;
    QLabel *cursorLabel_ = nullptr;

    bool navigating_ = false;
    QTimer listsTimer_;
    quint64 listsGeneration_ = ~quint64{0};
};

} // namespace dasm
