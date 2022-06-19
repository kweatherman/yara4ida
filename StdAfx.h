
// Common includes and global defs
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER		 0x0A00 // _WIN32_WINNT_WIN10
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <crtdbg.h>
#include <mmsystem.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <intrin.h>
#pragma intrinsic(memset, memcmp, memcpy, strcat, strcmp, strcpy, strlen, abs, fabs, labs, atan, atan2, tan, sqrt, sin, cos, _rotl)

#include <string>
#include <map>
#include <vector>

// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
//#define NO_OBSOLETE_FUNCS
// Nix the many warning about int type conversions
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#include <ida.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <typeinf.hpp>
#include <struct.hpp>
#include <nalt.hpp>
#pragma warning(pop)

// Qt libs
#include <QtCore/QTextStream>
#include <QtCore/QFile>
#include <QtWidgets/QApplication>
#include <QtWidgets/QProgressDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QTableView>
// IDA SDK Qt libs
#pragma comment(lib, "Qt5Core.lib")
#pragma comment(lib, "Qt5Gui.lib")
#pragma comment(lib, "Qt5Widgets.lib")

// QT_NO_UNICODE_LITERAL must be defined (best in preprocessor setting) so 
// Qt doesn't use a static string pool that will cause IDA to crash on unload.
#ifndef QT_NO_UNICODE_LITERAL
# error QT_NO_UNICODE_LITERAL must be defined to avoid Qt string crashes
#endif

#define STYLE_PATH ":/template/"

#define MSG_TAG "Yara4Ida: "
#include "Utility.h"

#define MY_VERSION MAKE_SEMANTIC_VERSION(VERSION_RELEASE, 1, 0, 0)

#include "libyara\include\yara.h"
#include "WaitBoxEx.h"
#define REFRESH_UI() { WaitBox::processIdaEvents(); }

// Chooser match container
struct MATCH
{
	YR_RULE* rule;
	ea_t address;	// RVA

	bool operator()(MATCH const& a, MATCH const& b) { return a.address < b.address; }
};
typedef std::vector<MATCH> MATCHES;
