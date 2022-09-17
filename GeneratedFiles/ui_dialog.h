/********************************************************************************
** Form generated from reading UI file 'dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.12
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_DIALOG_H
#define UI_DIALOG_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>

QT_BEGIN_NAMESPACE

class Ui_MainCIDialog
{
public:
    QDialogButtonBox *buttonBox;
    QCheckBox *checkBox1;
    QCheckBox *checkBox2;
    QCheckBox *checkBox3;
    QLabel *linkLabel;
    QLabel *image;
    QPushButton *pushButton1;

    void setupUi(QDialog *MainCIDialog)
    {
        if (MainCIDialog->objectName().isEmpty())
            MainCIDialog->setObjectName(QString::fromUtf8("MainCIDialog"));
        MainCIDialog->resize(292, 354);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MainCIDialog->sizePolicy().hasHeightForWidth());
        MainCIDialog->setSizePolicy(sizePolicy);
        MainCIDialog->setMinimumSize(QSize(292, 354));
        MainCIDialog->setMaximumSize(QSize(292, 354));
        MainCIDialog->setWindowTitle(QString::fromUtf8("Yara4Ida"));
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/template/icon.png"), QSize(), QIcon::Normal, QIcon::Off);
        MainCIDialog->setWindowIcon(icon);
#ifndef QT_NO_TOOLTIP
        MainCIDialog->setToolTip(QString::fromUtf8(""));
#endif // QT_NO_TOOLTIP
        MainCIDialog->setModal(true);
        buttonBox = new QDialogButtonBox(MainCIDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setGeometry(QRect(120, 320, 156, 24));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::NoButton);
        buttonBox->setCenterButtons(false);
        checkBox1 = new QCheckBox(MainCIDialog);
        checkBox1->setObjectName(QString::fromUtf8("checkBox1"));
        checkBox1->setGeometry(QRect(15, 148, 118, 17));
        QFont font;
        font.setFamily(QString::fromUtf8("Noto Sans"));
        font.setPointSize(10);
        checkBox1->setFont(font);
#ifndef QT_NO_TOOLTIP
        checkBox1->setToolTip(QString::fromUtf8("Automatically place match label comments."));
#endif // QT_NO_TOOLTIP
        checkBox2 = new QCheckBox(MainCIDialog);
        checkBox2->setObjectName(QString::fromUtf8("checkBox2"));
        checkBox2->setGeometry(QRect(15, 176, 116, 17));
        checkBox2->setFont(font);
#ifndef QT_NO_TOOLTIP
        checkBox2->setToolTip(QString::fromUtf8("Force single thread, else use a thread per CPU core concurrent scan."));
#endif // QT_NO_TOOLTIP
        checkBox3 = new QCheckBox(MainCIDialog);
        checkBox3->setObjectName(QString::fromUtf8("checkBox3"));
        checkBox3->setGeometry(QRect(15, 202, 135, 17));
        checkBox3->setFont(font);
#ifndef QT_NO_TOOLTIP
        checkBox3->setToolTip(QString::fromUtf8("Show YARA rule warnings and additional processing messages."));
#endif // QT_NO_TOOLTIP
        linkLabel = new QLabel(MainCIDialog);
        linkLabel->setObjectName(QString::fromUtf8("linkLabel"));
        linkLabel->setGeometry(QRect(15, 280, 99, 16));
        linkLabel->setFont(font);
        linkLabel->setFrameShadow(QFrame::Sunken);
        linkLabel->setTextFormat(Qt::AutoText);
        linkLabel->setOpenExternalLinks(true);
        image = new QLabel(MainCIDialog);
        image->setObjectName(QString::fromUtf8("image"));
        image->setGeometry(QRect(0, 0, 292, 128));
#ifndef QT_NO_TOOLTIP
        image->setToolTip(QString::fromUtf8(""));
#endif // QT_NO_TOOLTIP
        image->setTextFormat(Qt::PlainText);
        image->setPixmap(QPixmap(QString::fromUtf8(":/template/banner.png")));
        image->setTextInteractionFlags(Qt::NoTextInteraction);
        pushButton1 = new QPushButton(MainCIDialog);
        pushButton1->setObjectName(QString::fromUtf8("pushButton1"));
        pushButton1->setGeometry(QRect(15, 240, 129, 27));
        pushButton1->setFont(font);
#ifndef QT_NO_TOOLTIP
        pushButton1->setToolTip(QString::fromUtf8("Select alternate YARA rule file to load. Default \\\"yara_rules\\\\default.yar\\\" from the IDA \\\"plugins\\\" folder."));
#endif // QT_NO_TOOLTIP
        pushButton1->setText(QString::fromUtf8("LOAD ALT RULES"));
        pushButton1->setAutoDefault(false);

        retranslateUi(MainCIDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), MainCIDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), MainCIDialog, SLOT(reject()));
        QObject::connect(pushButton1, SIGNAL(pressed()), MainCIDialog, SLOT(pressSelect()));

        QMetaObject::connectSlotsByName(MainCIDialog);
    } // setupUi

    void retranslateUi(QDialog *MainCIDialog)
    {
        checkBox1->setText(QApplication::translate("MainCIDialog", "Place comments", nullptr));
        checkBox2->setText(QApplication::translate("MainCIDialog", "Single threaded", nullptr));
        checkBox3->setText(QApplication::translate("MainCIDialog", "Verbose messages", nullptr));
#ifndef QT_NO_TOOLTIP
        linkLabel->setToolTip(QApplication::translate("MainCIDialog", "Click to open the Yara4Ida Github.", nullptr));
#endif // QT_NO_TOOLTIP
        linkLabel->setText(QApplication::translate("MainCIDialog", "<a href=\"https://github.com/kweatherman/yara4ida/\" style=\"color:#AEADA9;\">Yara4Ida Github</a>", nullptr));
        image->setText(QString());
        Q_UNUSED(MainCIDialog);
    } // retranslateUi

};

namespace Ui {
    class MainCIDialog: public Ui_MainCIDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_DIALOG_H
