#include "optionsdialog.h"
#include "ui_optionsdialog.h"

#include "bitcoinamountfield.h"
#include "bitcoinunits.h"
#include "monitoreddatamapper.h"
#include "netbase.h"
#include "optionsmodel.h"
#include "qvalidatedlineedit.h"
#include "qvaluecombobox.h"

#include <QCheckBox>
#include <QDir>
#include <QIntValidator>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QRegExp>
#include <QRegExpValidator>
#include <QTabWidget>
#include <QWidget>

OptionsDialog::OptionsDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::OptionsDialog),
    model(0),
    mapper(0),
    fRestartWarningDisplayed_Proxy(false),
    fRestartWarningDisplayed_Lang(false),
    fProxyIpValid(true)
{
    ui->setupUi(this);

    /* Network elements init */
#ifndef USE_UPNP
    ui->mapPortUpnp->setEnabled(false);
#endif

    ui->socksVersion->setEnabled(false);
    ui->socksVersion->addItem("5", 5);
    ui->socksVersion->addItem("4", 4);
    ui->socksVersion->setCurrentIndex(0);

    ui->proxyIp->setEnabled(false);
    ui->proxyPort->setEnabled(false);
    ui->proxyPort->setValidator(new QIntValidator(0, 65535, this));

    connect(ui->connectSocks, SIGNAL(toggled(bool)), ui->socksVersion, SLOT(setEnabled(bool)));
    connect(ui->connectSocks, SIGNAL(toggled(bool)), ui->proxyIp, SLOT(setEnabled(bool)));
    connect(ui->connectSocks, SIGNAL(toggled(bool)), ui->proxyPort, SLOT(setEnabled(bool)));

    ui->proxyIp->installEventFilter(this);

    /* Window elements init */
#ifdef Q_OS_MAC
    ui->tabWindow->setVisible(false);
#endif

    /* Display elements init */
    QDir translations(":translations");
    ui->lang->addItem(QString("(") + tr("default") + QString(")"), QVariant(""));
    foreach(const QString &langStr, translations.entryList())
    {
        ui->lang->addItem(langStr, QVariant(langStr));
    }

    ui->unit->setModel(new BitcoinUnits(this));

    connect(ui->connectSocks, SIGNAL(clicked(bool)), this, SLOT(showRestartWarning_Proxy()));
    connect(ui->lang, SIGNAL(activated(int)), this, SLOT(showRestartWarning_Lang()));

    /* Widget-to-option mapper */
    mapper = new MonitoredDataMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
    mapper->setOrientation(Qt::Vertical);

    /* enable save buttons when data modified */
    connect(mapper, SIGNAL(viewModified()), this, SLOT(enableSaveButtons()));
    /* disable save buttons when new data loaded */
    connect(mapper, SIGNAL(currentIndexChanged(int)), this, SLOT(disableSaveButtons()));
    /* disable/enable save buttons when proxy IP is invalid/valid */
    connect(this, SIGNAL(proxyIpValid(bool)), this, SLOT(setSaveButtonState(bool)));
}

OptionsDialog::~OptionsDialog()
{
    delete ui;
}

void OptionsDialog::setModel(OptionsModel *model)
{
    this->model = model;

    if(model)
    {
        connect(model, SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        mapper->setModel(model);
        setMapper();
        mapper->toFirst();
    }

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void OptionsDialog::setMapper()
{
    /* Main */
    mapper->addMapping(ui->transactionFee, OptionsModel::Fee);
    mapper->addMapping(ui->bitcoinAtStartup, OptionsModel::StartAtStartup);

    /* Network */
    mapper->addMapping(ui->mapPortUpnp, OptionsModel::MapPortUPnP);
    mapper->addMapping(ui->connectSocks, OptionsModel::ProxyUse);
    mapper->addMapping(ui->socksVersion, OptionsModel::ProxySocksVersion);
    mapper->addMapping(ui->proxyIp, OptionsModel::ProxyIP);
    mapper->addMapping(ui->proxyPort, OptionsModel::ProxyPort);

    /* Window */
#ifndef Q_OS_MAC
    mapper->addMapping(ui->minimizeToTray, OptionsModel::MinimizeToTray);
    mapper->addMapping(ui->minimizeOnClose, OptionsModel::MinimizeOnClose);
	mapper->addMapping(ui->coinControlFeatures, OptionsModel::CoinControlFeatures);
#endif

    /* Display */
    mapper->addMapping(ui->lang, OptionsModel::Language);
    mapper->addMapping(ui->unit, OptionsModel::DisplayUnit);
    mapper->addMapping(ui->displayAddresses, OptionsModel::DisplayAddresses);
    mapper->addMapping(ui->useVTheme, OptionsModel::UseVTheme);
}

void OptionsDialog::enableSaveButtons()
{
    // prevent enabling of the save buttons when data modified, if there is an invalid proxy address present
    if(fProxyIpValid)
        setSaveButtonState(true);
}

void OptionsDialog::disableSaveButtons()
{
    setSaveButtonState(false);
}

void OptionsDialog::setSaveButtonState(bool fState)
{
    ui->applyButton->setEnabled(fState);
    ui->okButton->setEnabled(fState);
}

void OptionsDialog::on_okButton_clicked()
{
    mapper->submit();
    accept();
}

void OptionsDialog::on_cancelButton_clicked()
{
    reject();
}

void OptionsDialog::on_applyButton_clicked()
{
    mapper->submit();
    ui->applyButton->setEnabled(false);
}

void OptionsDialog::showRestartWarning_Proxy()
{
    if(!fRestartWarningDisplayed_Proxy)
    {
        QMessageBox::warning(this, tr("Warning"), tr("This setting will take effect after restarting Version."), QMessageBox::Ok);
        fRestartWarningDisplayed_Proxy = true;
    }
}

void OptionsDialog::showRestartWarning_Lang()
{
    if(!fRestartWarningDisplayed_Lang)
    {
        QMessageBox::warning(this, tr("Warning"), tr("This setting will take effect after restarting Version."), QMessageBox::Ok);
        fRestartWarningDisplayed_Lang = true;
    }
}

void OptionsDialog::updateDisplayUnit()
{
    if(model)
    {
        // Update transactionFee with the current unit
        ui->transactionFee->setDisplayUnit(model->getDisplayUnit());
    }
}

bool OptionsDialog::eventFilter(QObject *object, QEvent *event)
{
    if(object == ui->proxyIp && event->type() == QEvent::FocusOut)
    {
        // Check proxyIP for a valid IPv4/IPv6 address
        CService addr;
        if(!LookupNumeric(ui->proxyIp->text().toStdString().c_str(), addr))
        {
            ui->proxyIp->setValid(false);
            fProxyIpValid = false;
            ui->statusLabel->setStyleSheet("QLabel { color: red; }");
            ui->statusLabel->setText(tr("The supplied proxy address is invalid."));
            emit proxyIpValid(false);
        }
        else
        {
            fProxyIpValid = true;
            ui->statusLabel->clear();
            emit proxyIpValid(true);
        }
    }
    return QDialog::eventFilter(object, event);
}
