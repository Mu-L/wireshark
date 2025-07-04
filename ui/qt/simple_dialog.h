/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SIMPLE_DIALOG_H
#define SIMPLE_DIALOG_H

#include <config.h>

#include <stdio.h>

#include "ui/simple_dialog.h"

#include <QPair>
#include <QString>

class QCheckBox;
class QMessageBox;
class QWidget;

// This might be constructed before Qt is initialized and must be a plain, non-Qt object.
class SimpleDialog
{
public:
    explicit SimpleDialog(QWidget *parent, ESD_TYPE_E type, int btn_mask, const char *msg_format, va_list ap, QString secondary_msg = QString());
    ~SimpleDialog();

    static void displayQueuedMessages(QWidget *parent = 0);
    static QString dontShowThisAgain();
    void setInformativeText(QString text) { informative_text_ = text; }
    void setDetailedText(QString text) { detailed_text_ = text; }
    void setCheckBox(QCheckBox *cb) { check_box_ = cb; }
    int exec();
    void show();

private:
    QString informative_text_;
    QString detailed_text_;
    QCheckBox *check_box_;
    QMessageBox *message_box_;
};

#endif // SIMPLE_DIALOG_H
