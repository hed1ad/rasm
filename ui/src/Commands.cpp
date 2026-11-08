#include "Commands.h"

#include <QWidget>

namespace dasm {

QAction *CommandRegistry::add(const QString &id, const QString &title,
                              const QKeySequence &key, QWidget *scope,
                              std::function<void()> run,
                              Qt::ShortcutContext context) {
    auto *action = new QAction(title, scope);
    action->setObjectName(id);
    if (!key.isEmpty()) {
        action->setShortcut(key);
        action->setShortcutContext(context);
    }
    QObject::connect(action, &QAction::triggered, scope, [run = std::move(run)] { run(); });
    scope->addAction(action);
    commands_.push_back({id, title, key, action});
    return action;
}

const Command *CommandRegistry::find(const QString &id) const {
    for (const auto &c : commands_) {
        if (c.id == id) return &c;
    }
    return nullptr;
}

bool CommandRegistry::run(const QString &id) const {
    const Command *c = find(id);
    if (!c || !c->action->isEnabled()) return false;
    c->action->trigger();
    return true;
}

} // namespace dasm
