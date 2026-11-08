// dasm-gui entry point. The Qt event loop belongs to C++ (ADR 0005).
//
//   dasm-gui [--mock] [FILE]
//   dasm-gui --mock --screenshot out.png [--palette TEXT]   (offscreen use)

#include <QApplication>
#include <QCommandLineParser>
#include <QTimer>

#include "ListingView.h"
#include "MainWindow.h"
#include "Palette.h"

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("dasm"));
    dasm::applyTheme();

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("dasm disassembler"));
    parser.addHelpOption();
    parser.addOption({QStringLiteral("mock"), QStringLiteral("Open the synthetic program instead of a file.")});
    parser.addOption({QStringLiteral("screenshot"), QStringLiteral("Save a screenshot of the window and exit."),
                      QStringLiteral("png")});
    parser.addOption({QStringLiteral("palette"), QStringLiteral("With --screenshot: open the palette with this text."),
                      QStringLiteral("text")});
    parser.addPositionalArgument(QStringLiteral("file"), QStringLiteral("Binary to open."));
    parser.process(app);

    dasm::MainWindow win;
    win.show();

    if (parser.isSet(QStringLiteral("mock"))) {
        win.openMock();
    } else if (!parser.positionalArguments().isEmpty()) {
        win.openFile(parser.positionalArguments().first());
    }

    if (parser.isSet(QStringLiteral("screenshot"))) {
        const QString out = parser.value(QStringLiteral("screenshot"));
        const QString pal = parser.value(QStringLiteral("palette"));
        QObject::connect(&win.session(), &SessionObject::opened, &win, [&win, out, pal] {
            QTimer::singleShot(400, &win, [&win, out, pal] {
                if (!pal.isEmpty()) win.palette()->openWith(pal);
                QTimer::singleShot(200, &win, [&win, out] {
                    const bool ok = win.grab().save(out);
                    QApplication::exit(ok ? 0 : 1);
                });
            });
        });
        QTimer::singleShot(15000, &app, [] { QApplication::exit(2); });
    }
    return app.exec();
}
