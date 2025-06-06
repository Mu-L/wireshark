/* interface_frame.cpp
 * Display of interfaces, including their respective data, and the
 * capability to filter interfaces by type
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include <ui_interface_frame.h>

#include "capture/capture_ifinfo.h"

#ifdef Q_OS_WIN
#include "capture/capture-wpcap.h"
#endif

#include "ui/qt/interface_frame.h"
#include <ui/qt/simple_dialog.h>
#include <ui/qt/main_application.h>

#include <ui/qt/models/interface_tree_model.h>
#include <ui/qt/models/sparkline_delegate.h>

#include <ui/qt/utils/color_utils.h>


#include "extcap.h"

#include <ui/recent.h>
#include "ui/capture_opts.h"
#include "ui/capture_globals.h"
#include <ui/iface_lists.h>
#include <wsutil/application_flavor.h>
#include <wsutil/utf8_entities.h>
#ifdef Q_OS_UNIX
#include <unistd.h> /* for access() and X_OK */
#include <wsutil/filesystem.h>
#endif

#include <QDesktopServices>
#include <QFrame>
#include <QHBoxLayout>
#include <QItemSelection>
#include <QLabel>
#include <QPushButton>
#include <QUrl>
#include <QMutex>
#include <QDebug>

#include <epan/prefs.h>

#define BTN_IFTYPE_PROPERTY "ifType"

#ifdef HAVE_LIBPCAP
const int stat_update_interval_ = 1000; // ms
#endif
const char *no_capture_link = "#no_capture";

static QMutex scan_mutex;

InterfaceFrame::InterfaceFrame(QWidget * parent)
: QFrame(parent),
  ui(new Ui::InterfaceFrame)
  , proxy_model_(Q_NULLPTR)
  , source_model_(Q_NULLPTR)
  , info_model_(this)
#ifdef HAVE_LIBPCAP
  ,stat_timer_(NULL)
#endif // HAVE_LIBPCAP
{
    ui->setupUi(this);

    setStyleSheet(QStringLiteral(
                      "QFrame {"
                      "  border: 0;"
                      "}"
                      "QTreeView {"
                      "  border: 0;"
                      "}"
                      ));

    ui->warningLabel->hide();

#ifdef Q_OS_MAC
    ui->interfaceTree->setAttribute(Qt::WA_MacShowFocusRect, false);
#endif

    /* TODO: There must be a better way to do this */
    ifTypeDescription.insert(IF_WIRED, tr("Wired"));
    ifTypeDescription.insert(IF_AIRPCAP, tr("AirPCAP"));
    ifTypeDescription.insert(IF_PIPE, tr("Pipe"));
    ifTypeDescription.insert(IF_STDIN, tr("STDIN"));
    ifTypeDescription.insert(IF_BLUETOOTH, tr("Bluetooth"));
    ifTypeDescription.insert(IF_WIRELESS, tr("Wireless"));
    ifTypeDescription.insert(IF_DIALUP, tr("Dial-Up"));
    ifTypeDescription.insert(IF_USB, tr("USB"));
    ifTypeDescription.insert(IF_EXTCAP, tr("External Capture"));
    ifTypeDescription.insert(IF_VIRTUAL, tr ("Virtual"));

    QList<InterfaceTreeColumns> columns;
    columns.append(IFTREE_COL_EXTCAP);
    columns.append(IFTREE_COL_DISPLAY_NAME);
    columns.append(IFTREE_COL_STATS);
    proxy_model_.setColumns(columns);
    proxy_model_.setStoreOnChange(true);
    proxy_model_.setSortByActivity(true);
    proxy_model_.setSourceModel(&source_model_);

    info_model_.setSourceModel(&proxy_model_);
    info_model_.setColumn(static_cast<int>(columns.indexOf(IFTREE_COL_STATS)));

    ui->interfaceTree->setModel(&info_model_);
    ui->interfaceTree->setSortingEnabled(true);

    ui->interfaceTree->setItemDelegateForColumn(proxy_model_.mapSourceToColumn(IFTREE_COL_STATS), new SparkLineDelegate(this));

    ui->interfaceTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->interfaceTree, &QTreeView::customContextMenuRequested, this, &InterfaceFrame::showContextMenu);

    connect(mainApp, &MainApplication::appInitialized, this, &InterfaceFrame::interfaceListChanged);
    connect(mainApp, &MainApplication::localInterfaceListChanged, this, &InterfaceFrame::interfaceListChanged);

    connect(ui->interfaceTree->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &InterfaceFrame::interfaceTreeSelectionChanged);
}

InterfaceFrame::~InterfaceFrame()
{
    delete ui;
}

QMenu * InterfaceFrame::getSelectionMenu()
{
    QMenu * contextMenu = new QMenu(this);
    QList<int> typesDisplayed = proxy_model_.typesDisplayed();

    QMap<int, QString>::const_iterator it = ifTypeDescription.constBegin();
    while (it != ifTypeDescription.constEnd())
    {
        int ifType = it.key();

        if (typesDisplayed.contains(ifType))
        {
            QAction *endp_action = new QAction(it.value(), this);
            endp_action->setData(QVariant::fromValue(ifType));
            endp_action->setCheckable(true);
            endp_action->setChecked(proxy_model_.isInterfaceTypeShown(ifType));
            connect(endp_action, &QAction::triggered, this, &InterfaceFrame::triggeredIfTypeButton);
            contextMenu->addAction(endp_action);
        }
        ++it;
    }

#ifdef HAVE_PCAP_REMOTE
    if (proxy_model_.remoteInterfacesExist())
    {
        QAction * toggleRemoteAction = new QAction(tr("Remote interfaces"), this);
        toggleRemoteAction->setCheckable(true);
        toggleRemoteAction->setChecked(proxy_model_.remoteDisplay());
        connect(toggleRemoteAction, &QAction::triggered, this, &InterfaceFrame::toggleRemoteInterfaces);
        contextMenu->addAction(toggleRemoteAction);
    }
#endif

    contextMenu->addSeparator();
    QAction * toggleHideAction = new QAction(tr("Show hidden interfaces"), this);
    toggleHideAction->setCheckable(true);
    toggleHideAction->setChecked(! proxy_model_.filterHidden());
    connect(toggleHideAction, &QAction::triggered, this, &InterfaceFrame::toggleHiddenInterfaces);
    contextMenu->addAction(toggleHideAction);

    return contextMenu;
}

int InterfaceFrame::interfacesHidden()
{
    return proxy_model_.interfacesHidden();
}

int InterfaceFrame::interfacesPresent()
{
    return source_model_.rowCount() - proxy_model_.interfacesHidden();
}

void InterfaceFrame::ensureSelectedInterface()
{
#ifdef HAVE_LIBPCAP
    if (interfacesPresent() < 1) return;

    if (source_model_.selectedDevices().count() < 1) {
        QModelIndex first_idx = info_model_.mapFromSource(proxy_model_.index(0, 0));
        ui->interfaceTree->setCurrentIndex(first_idx);
    }

    ui->interfaceTree->setFocus();
#endif
}

void InterfaceFrame::hideEvent(QHideEvent *) {
#ifdef HAVE_LIBPCAP
    if (stat_timer_)
        stat_timer_->stop();
    source_model_.stopStatistic();
#endif // HAVE_LIBPCAP
}

void InterfaceFrame::showEvent(QShowEvent *) {

#ifdef HAVE_LIBPCAP
    if (stat_timer_)
        stat_timer_->start(stat_update_interval_);
#endif // HAVE_LIBPCAP
}

#ifdef HAVE_LIBPCAP
void InterfaceFrame::scanLocalInterfaces(GList *filter_list)
{
    GList *if_list = NULL;
    if (scan_mutex.tryLock()) {
        if (isVisible()) {
            source_model_.stopStatistic();
            if_stat_cache_t * stat_cache = capture_interface_stat_start(&global_capture_opts, &if_list);
            source_model_.setCache(stat_cache);
        }
        mainApp->setInterfaceList(if_list);
        free_interface_list(if_list);
        scan_local_interfaces_filtered(filter_list, main_window_update);
        mainApp->emitAppSignal(MainApplication::LocalInterfacesChanged);
        scan_mutex.unlock();
    } else {
        qDebug() << "scan mutex locked, can't scan interfaces";
    }
}
#endif // HAVE_LIBPCAP

void InterfaceFrame::actionButton_toggled(bool checked)
{
    QVariant ifType = sender()->property(BTN_IFTYPE_PROPERTY);
    if (ifType.isValid())
    {
        proxy_model_.setInterfaceTypeVisible(ifType.toInt(), checked);
    }

    resetInterfaceTreeDisplay();
}

void InterfaceFrame::triggeredIfTypeButton()
{
    QAction *sender = qobject_cast<QAction *>(QObject::sender());
    if (sender)
    {
        int ifType = sender->data().value<int>();
        proxy_model_.toggleTypeVisibility(ifType);

        resetInterfaceTreeDisplay();
        emit typeSelectionChanged();
    }
}

void InterfaceFrame::interfaceListChanged()
{
    info_model_.clearInfos();
    if (prefs.capture_no_extcap)
        info_model_.appendInfo(tr("External capture interfaces disabled."));

    resetInterfaceTreeDisplay();
    // Ensure that device selection is consistent with the displayed selection.
    updateSelectedInterfaces();

#ifdef HAVE_LIBPCAP
    if (!stat_timer_) {
        updateStatistics();
        stat_timer_ = new QTimer(this);
        connect(stat_timer_, &QTimer::timeout, this, &InterfaceFrame::updateStatistics);
        stat_timer_->start(stat_update_interval_);
    }
#endif
}

void InterfaceFrame::toggleHiddenInterfaces()
{
    source_model_.interfaceListChanged();
    proxy_model_.toggleFilterHidden();

    emit typeSelectionChanged();
}

#ifdef HAVE_PCAP_REMOTE
void InterfaceFrame::toggleRemoteInterfaces()
{
    proxy_model_.toggleRemoteDisplay();
    emit typeSelectionChanged();
}
#endif

void InterfaceFrame::resetInterfaceTreeDisplay()
{
    ui->warningLabel->hide();
    ui->warningLabel->clear();

    ui->warningLabel->setStyleSheet(QStringLiteral(
                "QLabel {"
                "  border-radius: 0.5em;"
                "  padding: 0.33em;"
                "  margin-bottom: 0.25em;"
                // We might want to transition this to normal colors this after a timeout.
                "  background-color: %2;"
                "}"
                ).arg(ColorUtils::warningBackground().name()));

#ifdef HAVE_LIBPCAP
#ifdef Q_OS_WIN
    if (application_flavor_is_wireshark()) {
        if (caplibs_have_winpcap()) {
            // We have gotten reports of the WinPcap uninstaller not correctly
            // removing all its DLLs and this causing conflicts:
            // https://gitlab.com/wireshark/wireshark/-/issues/14160
            // https://gitlab.com/wireshark/wireshark/-/issues/14543
            ui->warningLabel->setText(tr(
                "<p>"
                "Local interfaces are unavailable because WinPcap is installed but is no longer supported."
                "</p><p>"
                "You can fix this by uninstalling WinPcap and installing <a href=\"https://npcap.com/\">Npcap</a>."
                "</p>"));
        } else if (!has_npcap) {
            ui->warningLabel->setText(tr(
                "<p>"
                "Local interfaces are unavailable because no packet capture driver is installed."
                "</p><p>"
                "You can fix this by installing <a href=\"https://npcap.com/\">Npcap</a>."
                "</p>"));
        } else if (!npf_sys_is_running()) {
            ui->warningLabel->setText(tr(
                "<p>"
                "Local interfaces are unavailable because the packet capture driver isn't loaded."
                "</p><p>"
                "You can fix this by running <pre>net start npcap</pre> if you have Npcap installed."
                " The command must be run as Administrator."
                "</p>"));
        }
    }
#endif

    if (!haveLocalCapturePermissions())
    {
#ifdef Q_OS_MAC
        //
        // NOTE: if you change this text, you must also change the
        // definition of PLATFORM_PERMISSIONS_SUGGESTION that is
        // used if __APPLE__ is defined, so that it reflects the
        // new message text.
        //
        QString install_chmodbpf_path = QStringLiteral("%1/../Resources/Extras/Install ChmodBPF.pkg").arg(mainApp->applicationDirPath());
        ui->warningLabel->setText(tr(
            "<p>"
            "You don't have permission to capture on local interfaces."
            "</p><p>"
            "You can fix this by <a href=\"file://%1\">installing ChmodBPF</a>."
            "</p>")
            .arg(install_chmodbpf_path));
#else
        //
        // XXX - should this give similar platform-dependent recommendations,
        // just as dumpcap gives platform-dependent recommendations in its
        // PLATFORM_PERMISSIONS_SUGGESTION #define?
        //
        ui->warningLabel->setText(tr("You don't have permission to capture on local interfaces."));
#endif
    }

    if (proxy_model_.rowCount() == 0)
    {
        ui->warningLabel->setText(tr("No interfaces found."));
        ui->warningLabel->setText(proxy_model_.interfaceError());
        if (prefs.capture_no_interface_load) {
            ui->warningLabel->setText(tr("Interfaces not loaded (due to preference). Go to Capture " UTF8_RIGHTWARDS_ARROW " Refresh Interfaces to load."));
        }
    }

    // XXX Should we have a separate recent pref for each message?
    if (!ui->warningLabel->text().isEmpty() && recent.sys_warn_if_no_capture)
    {
        QString warning_text = ui->warningLabel->text();
        warning_text.append(QStringLiteral("<p><a href=\"%1\">%2</a></p>")
                            .arg(no_capture_link)
                            .arg(SimpleDialog::dontShowThisAgain()));
        ui->warningLabel->setText(warning_text);

        ui->warningLabel->show();
    }
#endif // HAVE_LIBPCAP

    if (proxy_model_.rowCount() > 0)
    {
        ui->interfaceTree->show();
        ui->interfaceTree->resizeColumnToContents(proxy_model_.mapSourceToColumn(IFTREE_COL_EXTCAP));
        ui->interfaceTree->resizeColumnToContents(proxy_model_.mapSourceToColumn(IFTREE_COL_DISPLAY_NAME));
        ui->interfaceTree->resizeColumnToContents(proxy_model_.mapSourceToColumn(IFTREE_COL_STATS));
    }
    else
    {
        ui->interfaceTree->hide();
    }
}

// XXX Should this be in capture/capture-pcap-util.[ch]?
bool InterfaceFrame::haveLocalCapturePermissions() const
{
#ifdef Q_OS_MAC
    if (application_flavor_is_wireshark()) {
        QFileInfo bpf0_fi = QFileInfo("/dev/bpf0");
        return bpf0_fi.isReadable() && bpf0_fi.isWritable();
    } else {
        return true;
    }
#elif defined(Q_OS_UNIX)
    char *dumpcap_bin = get_executable_path("dumpcap");
    bool executable = access(dumpcap_bin, X_OK) == 0;
    g_free(dumpcap_bin);
    return executable;
#else
    // XXX Add checks for other platforms.
    return true;
#endif
}

void InterfaceFrame::updateSelectedInterfaces()
{
    if (source_model_.rowCount() == 0)
        return;
#ifdef HAVE_LIBPCAP
    QItemSelection sourceSelection = source_model_.selectedDevices();
    QItemSelection mySelection = info_model_.mapSelectionFromSource(proxy_model_.mapSelectionFromSource(sourceSelection));

    ui->interfaceTree->selectionModel()->clearSelection();
    ui->interfaceTree->selectionModel()->select(mySelection, QItemSelectionModel::SelectCurrent);
#endif
}

void InterfaceFrame::interfaceTreeSelectionChanged(const QItemSelection & selected, const QItemSelection & deselected)
{
    if (selected.count() == 0 && deselected.count() == 0)
        return;
    if (source_model_.rowCount() == 0)
        return;

#ifdef HAVE_LIBPCAP
    /* Take all selected interfaces, not just the newly ones */
    QItemSelection allSelected = ui->interfaceTree->selectionModel()->selection();
    QItemSelection sourceSelection = proxy_model_.mapSelectionToSource(info_model_.mapSelectionToSource(allSelected));

    if (source_model_.updateSelectedDevices(sourceSelection))
        emit itemSelectionChanged();
#endif
}

void InterfaceFrame::on_interfaceTree_doubleClicked(const QModelIndex &index)
{
    QModelIndex realIndex = proxy_model_.mapToSource(info_model_.mapToSource(index));

    if (! realIndex.isValid())
        return;

    QStringList interfaces;

#ifdef HAVE_LIBPCAP

    QString device_name = source_model_.getColumnContent(realIndex.row(), IFTREE_COL_NAME).toString();
    QString extcap_string = source_model_.getColumnContent(realIndex.row(), IFTREE_COL_EXTCAP_PATH).toString();

    interfaces << device_name;

    /* We trust the string here. If this interface is really extcap, the string is
     * being checked immediately before the dialog is being generated */
    if (extcap_string.length() > 0)
    {
        /* this checks if configuration is required and not yet provided or saved via prefs */
        if (extcap_requires_configuration((const char *)(device_name.toStdString().c_str())))
        {
            emit showExtcapOptions(device_name, true);
            return;
        }
    }
#endif

    // Start capture for all columns except the first one with extcap
    if (IFTREE_COL_EXTCAP != realIndex.column()) {
        startCapture(interfaces);
    }
}

#ifdef HAVE_LIBPCAP
void InterfaceFrame::on_interfaceTree_clicked(const QModelIndex &index)
{
    if (index.column() == 0)
    {
        QModelIndex realIndex = proxy_model_.mapToSource(info_model_.mapToSource(index));

        if (! realIndex.isValid())
            return;

        QString device_name = source_model_.getColumnContent(realIndex.row(), IFTREE_COL_NAME).toString();
        QString extcap_string = source_model_.getColumnContent(realIndex.row(), IFTREE_COL_EXTCAP_PATH).toString();

        /* We trust the string here. If this interface is really extcap, the string is
         * being checked immediately before the dialog is being generated */
        if (extcap_string.length() > 0)
        {
            /* this checks if configuration is required and not yet provided or saved via prefs */
            if (extcap_has_configuration((const char *)(device_name.toStdString().c_str())))
            {
                emit showExtcapOptions(device_name, false);
                return;
            }
        }
    }
}
#endif

void InterfaceFrame::updateStatistics(void)
{
    if (source_model_.rowCount() == 0)
        return;

#ifdef HAVE_LIBPCAP

    for (int idx = 0; idx < source_model_.rowCount(); idx++)
    {
        QModelIndex selectIndex = info_model_.mapFromSource(proxy_model_.mapFromSource(source_model_.index(idx, 0)));

        /* Proxy model has not masked out the interface */
        if (selectIndex.isValid())
            source_model_.updateStatistic(idx);
    }
#endif
}

void InterfaceFrame::showRunOnFile(void)
{
    ui->warningLabel->setText("Interfaces not loaded on startup (run on capture file). Go to Capture -> Refresh Interfaces to load.");
}

void InterfaceFrame::showContextMenu(QPoint pos)
{
    QMenu * ctx_menu = new QMenu(this);
    // Work around QTBUG-106718. For some reason Qt::WA_DeleteOnClose +
    // Qt::QueuedConnection don't work here.
    QObject::connect(ctx_menu, &QMenu::triggered, ctx_menu, &QMenu::deleteLater);

    ctx_menu->addAction(tr("Start capture"), this, [=] () {
        QStringList ifaces;
        QModelIndexList selIndices = ui->interfaceTree->selectionModel()->selectedIndexes();
        foreach(QModelIndex idx, selIndices)
        {
            QModelIndex realIndex = proxy_model_.mapToSource(info_model_.mapToSource(idx));
            if (realIndex.column() != IFTREE_COL_NAME)
                realIndex = realIndex.sibling(realIndex.row(), IFTREE_COL_NAME);
            QString name = realIndex.data(Qt::DisplayRole).toString();
            if (! ifaces.contains(name))
                ifaces << name;
        }

        startCapture(ifaces);
    });

    ctx_menu->addSeparator();

    QModelIndex actIndex = ui->interfaceTree->indexAt(pos);
    QModelIndex realIndex = proxy_model_.mapToSource(info_model_.mapToSource(actIndex));
    bool isHidden = realIndex.sibling(realIndex.row(), IFTREE_COL_HIDDEN).data(Qt::UserRole).toBool();
    QAction * hideAction = ctx_menu->addAction(tr("Hide Interface"), this, [=] () {
        /* Attention! Only realIndex.row is a 1:1 correlation to all_ifaces */
        interface_t *device = &g_array_index(global_capture_opts.all_ifaces, interface_t, realIndex.row());
        device->hidden = ! device->hidden;
        mainApp->emitAppSignal(MainApplication::LocalInterfacesChanged);
    });
    hideAction->setCheckable(true);
    hideAction->setChecked(isHidden);

    ctx_menu->popup(ui->interfaceTree->mapToGlobal(pos));
}

void InterfaceFrame::on_warningLabel_linkActivated(const QString &link)
{
    if (link.compare(no_capture_link) == 0) {
        recent.sys_warn_if_no_capture = false;
        resetInterfaceTreeDisplay();
    } else {
        QDesktopServices::openUrl(QUrl(link));
    }
}
