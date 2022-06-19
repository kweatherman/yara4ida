
// Desc: Main dialog handler
#include "stdafx.h"
#include "MainDialog.h"

#include <QtWidgets/QDialogButtonBox>

extern void AltFileBtnHandler();

MainDialog::MainDialog(BOOL &optionPlaceComments, BOOL &optionSingleThread, BOOL &optionVerbose) : QDialog(QApplication::activeWindow(), 0)
{
    Ui::MainCIDialog::setupUi(this);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    buttonBox->addButton("CONTINUE", QDialogButtonBox::AcceptRole);
    buttonBox->addButton("CANCEL", QDialogButtonBox::RejectRole);

    #define INITSTATE(obj,state) obj->setCheckState((state == TRUE) ? Qt::Checked : Qt::Unchecked);
    INITSTATE(checkBox1, optionPlaceComments);
    INITSTATE(checkBox2, optionSingleThread);
    INITSTATE(checkBox3, optionVerbose);
    #undef INITSTATE

    // Apply style sheet
    QFile file(STYLE_PATH "style.qss");
    if (file.open(QFile::ReadOnly | QFile::Text))
        setStyleSheet(QTextStream(&file).readAll());
}

// On "LOAD ALT RULES" press
void MainDialog::pressSelect()
{
    AltFileBtnHandler();
}

// Do main dialog, return TRUE if canceled
BOOL doMainDialog(BOOL &optionPlaceComments, BOOL &optionSingleThread, BOOL &optionVerbose)
{
	BOOL result = TRUE;
    MainDialog *dlg = new MainDialog(optionPlaceComments, optionSingleThread, optionVerbose);

    // Set Dialog title with version number
	qstring version, tmp;
	version.sprnt("Yara for IDA %s", GetVersionString(MY_VERSION, tmp).c_str());
    dlg->setWindowTitle(version.c_str());

    if (dlg->exec())
    {
        #define CHECKSTATE(obj,var) var = dlg->obj->isChecked()
        CHECKSTATE(checkBox1, optionPlaceComments);
        CHECKSTATE(checkBox2, optionSingleThread);
        CHECKSTATE(checkBox3, optionVerbose);
        #undef CHECKSTATE
		result = FALSE;
    }
	delete dlg;
    return(result);
}