#pragma once
// Every user action is a command with an id and a shortcut, listed in the
// Ctrl+K palette (design: "everything is found through the palette").

#include <QAction>
#include <QKeySequence>
#include <QObject>
#include <QString>
#include <functional>
#include <map>
#include <vector>

namespace dasm {

struct Command {
    QString id;       // stable identifier, e.g. "edit.undo"
    QString title;    // palette text
    QKeySequence key; // may be empty
    QAction *action = nullptr;
};

class CommandRegistry : public QObject {
    Q_OBJECT
public:
    explicit CommandRegistry(QObject *parent = nullptr) : QObject(parent) {}

    // Creates the command's QAction. `scope` receives the action (so the
    // shortcut works); `context` limits where it fires.
    QAction *add(const QString &id, const QString &title, const QKeySequence &key,
                 QWidget *scope, std::function<void()> run,
                 Qt::ShortcutContext context = Qt::WindowShortcut);

    const std::vector<Command> &all() const { return commands_; }
    const Command *find(const QString &id) const;
    // Runs a command if it exists and is enabled.
    bool run(const QString &id) const;

private:
    std::vector<Command> commands_;
};

} // namespace dasm
