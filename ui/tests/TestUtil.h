#pragma once
// Helpers shared by the QtTest suites.

#include <QSignalSpy>
#include <QTest>
#include <memory>

#include "MainWindow.h"

namespace dasmtest {

// Opens the synthetic program on a bare session and waits until it is ready.
inline bool openMock(SessionObject &s) {
    QSignalSpy spy(&s, &SessionObject::opened);
    s.openMock();
    return spy.wait(5000) || spy.count() > 0;
}

// A shown main window with the synthetic program open.
inline std::unique_ptr<dasm::MainWindow> openedWindow() {
    auto win = std::make_unique<dasm::MainWindow>();
    win->resize(1200, 800);
    win->show();
    QSignalSpy spy(&win->session(), &SessionObject::opened);
    win->openMock();
    if (!spy.wait(5000) && spy.count() == 0) return nullptr;
    if (!QTest::qWaitForWindowExposed(win.get())) return nullptr;
    win->activateWindow();
    QApplication::processEvents();
    return win;
}

} // namespace dasmtest
