/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_DIALOG_H
#define PACKET_DIALOG_H

#include "wireshark_dialog.h"

#include "epan/epan_dissect.h"
#include "wiretap/wtap.h"
#include "wsutil/buffer.h"

#include <ui/qt/utils/field_information.h>

class DataSourceTab;
class ProtoTree;

namespace Ui {
class PacketDialog;
}

class PacketDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit PacketDialog(QWidget &parent, CaptureFile &cf, frame_data *fdata);
    ~PacketDialog();

protected:
    void captureFileClosing();

signals:
    void showProtocolPreferences(const QString module_name);
    void editProtocolPreference(pref_t *pref, module_t *module);

private slots:
    void on_buttonBox_helpRequested();
#if QT_VERSION >= QT_VERSION_CHECK(6, 7, 0)
    void viewVisibilityStateChanged(Qt::CheckState);
#else
    void viewVisibilityStateChanged(int);
#endif
    void layoutChanged(int);

    void setHintText(FieldInformation *);
    void setHintTextSelected(FieldInformation*);

private:
    Ui::PacketDialog *ui;

    pref_t *pref_packet_dialog_layout_;
    QString col_info_;
    ProtoTree *proto_tree_;
    DataSourceTab *data_source_tab_;
    wtap_rec rec_;
    epan_dissect_t edt_;
};

#endif // PACKET_DIALOG_H
