/*
 * W.J. van der Laan 2011-2012
 * The Version Developers 2018
 */
#include "bitcoingui.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "guiutil.h"

#include "init.h"
#include "ui_interface.h"
#include "qtipcserver.h"

#include <QApplication>
#include <QMessageBox>
#if QT_VERSION < 0x050000
#include <QTextCodec>
#endif
#include <QLocale>
#include <QTranslator>
#include <QSplashScreen>
#include <QLibraryInfo>

#include <boost/interprocess/ipc/message_queue.hpp>
#include <boost/algorithm/string/predicate.hpp>

#if defined(BITCOIN_NEED_QT_PLUGINS) && !defined(_BITCOIN_QT_PLUGINS_INCLUDED)
#define _BITCOIN_QT_PLUGINS_INCLUDED
#define __INSURE__
#include <QtPlugin>
Q_IMPORT_PLUGIN(qcncodecs)
Q_IMPORT_PLUGIN(qjpcodecs)
Q_IMPORT_PLUGIN(qtwcodecs)
Q_IMPORT_PLUGIN(qkrcodecs)
Q_IMPORT_PLUGIN(qtaccessiblewidgets)
#endif

// Need a global reference for the notifications to find the GUI
static BitcoinGUI *guiref;
static QSplashScreen *splashref;

static void ThreadSafeMessageBox(const std::string& message, const std::string& caption, int style)
{
    // Message from network thread
    if(guiref)
    {
        bool modal = (style & CClientUIInterface::MODAL);
        // In case of modal message, use blocking connection to wait for user to click a button
        QMetaObject::invokeMethod(guiref, "message",
                                   modal ? GUIUtil::blockingGUIThreadConnection() : Qt::QueuedConnection,
                                   Q_ARG(QString, QString::fromStdString(caption)),
                                   Q_ARG(QString, QString::fromStdString(message)),
                                   Q_ARG(unsigned int, style));
    }
    else
    {
        printf("%s: %s\n", caption.c_str(), message.c_str());
        fprintf(stderr, "%s: %s\n", caption.c_str(), message.c_str());
    }
}

static bool ThreadSafeAskFee(int64_t nFeeRequired, const std::string& strCaption)
{
    if(!guiref)
        return false;
    if(nFeeRequired < MIN_TX_FEE || nFeeRequired <= nTransactionFee || fDaemon)
        return true;
    bool payFee = false;

    QMetaObject::invokeMethod(guiref, "askFee", GUIUtil::blockingGUIThreadConnection(),
                               Q_ARG(qint64, nFeeRequired),
                               Q_ARG(bool*, &payFee));

    return payFee;
}

static void ThreadSafeHandleURI(const std::string& strURI)
{
    if(!guiref)
        return;

    QMetaObject::invokeMethod(guiref, "handleURI", GUIUtil::blockingGUIThreadConnection(),
                               Q_ARG(QString, QString::fromStdString(strURI)));
}

static void InitMessage(const std::string &message)
{
    if(splashref)
    {
        splashref->showMessage("Personal Vault "  + QString::fromStdString(FormatFullVersion().c_str()) + " : " + QString::fromStdString(message), Qt::AlignTop|Qt::AlignHCenter, QColor(213,241,255));
        QApplication::instance()->processEvents();
    }
}

static void QueueShutdown()
{
    QMetaObject::invokeMethod(QCoreApplication::instance(), "quit", Qt::QueuedConnection);
}

/*
   Translate string to current locale using Qt.
 */
static std::string Translate(const char* psz)
{
    return QCoreApplication::translate("bitcoin-core", psz).toStdString();
}

/* Handle runaway exceptions. Shows a message box with the problem and quits the program.
 */
static void handleRunawayException(std::exception *e)
{
    PrintExceptionContinue(e, "Runaway exception");
    QMessageBox::critical(0, "Runaway exception", BitcoinGUI::tr("A fatal error occured. Version can no longer continue safely and will quit.") + QString("\n\n") + QString::fromStdString(strMiscWarning));
    exit(1);
}

#ifndef BITCOIN_QT_TEST
int main(int argc, char *argv[])
{
#if !defined(MAC_OSX) && !defined(WIN32)
// TODO: implement qtipcserver.cpp for Mac and Windows

    // Do this early as we don't want to bother initializing if we are just calling IPC
    for (int i = 1; i < argc; i++)
    {
        if (boost::algorithm::istarts_with(argv[i], "version:"))
        {
            const char *strURI = argv[i];
            try {
                boost::interprocess::message_queue mq(boost::interprocess::open_only, BITCOINURI_QUEUE_NAME);
                if(mq.try_send(strURI, strlen(strURI), 0))
                    exit(0);
                else
                    break;
            }
            catch (boost::interprocess::interprocess_exception &ex) {
                break;
            }
        }
    }
#endif

#if QT_VERSION < 0x0500
    // Internal string conversion is all UTF-8
    QTextCodec::setCodecForTr(QTextCodec::codecForName("UTF-8"));
    QTextCodec::setCodecForCStrings(QTextCodec::codecForTr());
#endif

    Q_INIT_RESOURCE(bitcoin);
    QApplication app(argc, argv);

    // Command-line options take precedence:
    ParseParameters(argc, argv);

    // ... then bitcoin.conf:
    if (!boost::filesystem::is_directory(GetDataDir(false)))
    {
        fprintf(stderr, "Error: Specified directory does not exist\n");
        return 1;
    }
    ReadConfigFile(mapArgs, mapMultiArgs);

    // Application identification (must be set before OptionsModel is initialized,
    // as it is used to locate QSettings)
    app.setOrganizationName("Version");
    app.setOrganizationDomain("version2.org");
    if(GetBoolArg("-testnet")) // Separate UI settings for testnet
        app.setApplicationName("Version-Qt-testnet");
    else
        app.setApplicationName("Version-Qt");

    // ... then GUI settings:
    OptionsModel optionsModel;

    // Get desired locale ("en_US") from command line or system locale
    QString lang_territory = QString::fromStdString(GetArg("-lang", QLocale::system().name().toStdString()));
    // Load language files for configured locale:
    // - First load the translator for the base language, without territory
    // - Then load the more specific locale translator
    QString lang = lang_territory;

    lang.truncate(lang_territory.lastIndexOf('_')); // "en"
    QTranslator qtTranslatorBase, qtTranslator, translatorBase, translator;

    qtTranslatorBase.load(QLibraryInfo::location(QLibraryInfo::TranslationsPath) + "/qt_" + lang);
    if (!qtTranslatorBase.isEmpty())
        app.installTranslator(&qtTranslatorBase);

    qtTranslator.load(QLibraryInfo::location(QLibraryInfo::TranslationsPath) + "/qt_" + lang_territory);
    if (!qtTranslator.isEmpty())
        app.installTranslator(&qtTranslator);

    translatorBase.load(":/translations/"+lang);
    if (!translatorBase.isEmpty())
        app.installTranslator(&translatorBase);

    translator.load(":/translations/"+lang_territory);
    if (!translator.isEmpty())
        app.installTranslator(&translator);
		
    // Subscribe to global signals from core
    uiInterface.ThreadSafeMessageBox.connect(ThreadSafeMessageBox);
    uiInterface.ThreadSafeAskFee.connect(ThreadSafeAskFee);
    uiInterface.ThreadSafeHandleURI.connect(ThreadSafeHandleURI);
    uiInterface.InitMessage.connect(InitMessage);
    uiInterface.QueueShutdown.connect(QueueShutdown);
    uiInterface.Translate.connect(Translate);
		
    // Show help message immediately after parsing command-line options (for "-lang") and setting locale,
    // but before showing splash screen.
    if (mapArgs.count("-?") || mapArgs.count("--help"))
    {
        GUIUtil::HelpMessageBox help;
        help.showOrPrint();
        return 1;
    }

    QSplashScreen splash(QPixmap(":/images/splash"), 0);
    if (GetBoolArg("-splash", true) && !GetBoolArg("-min"))
    {
        splash.show();
        splash.setAutoFillBackground(true);
        splashref = &splash;
    }

    app.processEvents();

    app.setQuitOnLastWindowClosed(false);

    try
    {
        // Regenerate startup link, to fix links to old versions
        if (GUIUtil::GetStartOnSystemStartup())
            GUIUtil::SetStartOnSystemStartup(true);
			
        BitcoinGUI window;
        guiref = &window;
        if(AppInit2())
        {
            {
                // Put this in a block, so that the Model objects are cleaned up before
                // calling Shutdown().

                optionsModel.Upgrade(); // Must be done after AppInit2

                if (splashref)
                    splash.finish(&window);

                ClientModel clientModel(&optionsModel);
                WalletModel walletModel(pwalletMain, &optionsModel);

                window.setClientModel(&clientModel);
                window.setWalletModel(&walletModel);

                // If -min option passed, start window minimized.
                if(GetBoolArg("-min"))
                {
                    window.showMinimized();
                }
                else
                {
                    window.show();
                }

#if !defined(MAC_OSX) && !defined(WIN32)
// TODO: implement qtipcserver.cpp for Mac and Windows

                // Place this here as guiref has to be defined if we dont want to lose URIs
                ipcInit();

                // Check for URI in argv
                for (int i = 1; i < argc; i++)
                {
                    if (boost::algorithm::istarts_with(argv[i], "version:"))
                    {
                        const char *strURI = argv[i];
                        try {
                            boost::interprocess::message_queue mq(boost::interprocess::open_only, BITCOINURI_QUEUE_NAME);
                            mq.try_send(strURI, strlen(strURI), 0);
                        }
                        catch (boost::interprocess::interprocess_exception &ex) {
                        }
                    }
                }
#endif
                app.exec();

                window.hide();
                window.setClientModel(0);
                window.setWalletModel(0);
                guiref = 0;
            }
            // Shutdown the core and it's threads, but don't exit Bitcoin-Qt here
            Shutdown(NULL);
        }
        else
        {
            return 1;
        }
    } catch (std::exception& e) {
        handleRunawayException(&e);
    } catch (...) {
        handleRunawayException(NULL);
    }
    return 0;
}
#endif // BITCOIN_QT_TEST
