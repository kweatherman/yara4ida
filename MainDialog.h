
// Main Dialog
#pragma once

#include "stdafx.h"
#include <QtWidgets/QDialog>

#include "ui_dialog.h"

class MainDialog : public QDialog, public Ui::MainCIDialog
{
    Q_OBJECT
public:
    MainDialog(BOOL &optionPlaceComments, BOOL &optionSingleThread, BOOL &optionVerbose);

private slots:
	void pressSelect();
};

// Do main dialog, return TRUE if canceled
BOOL doMainDialog(BOOL &optionPlaceStructs, BOOL &optionProcessStatic, BOOL &optionAudioOnDone);
