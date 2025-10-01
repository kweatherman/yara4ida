
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

#include <algorithm>
#include <string>
#include <map>
#include <vector>

// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
//#define NO_OBSOLETE_FUNCS
// Nix the many warning about int type conversions
#pragma warning(push)
#pragma warning(disable:4244) // conversion from 'ssize_t' to 'int', possible loss of data
#pragma warning(disable:4267) // conversion from 'size_t' to 'uint32', possible loss of data
#pragma warning(disable:4018) // warning C4018: '<': signed/unsigned mismatch
#include <ida.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <typeinf.hpp>
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
#pragma comment(lib, "Qt6Core.lib")
#pragma comment(lib, "Qt6Gui.lib")
#pragma comment(lib, "Qt6Widgets.lib")

#define STYLE_PATH ":/template/"

#define MSG_TAG "Yara4Ida: "
#include "Utility.h"

#define MY_VERSION MAKE_SEMANTIC_VERSION(VERSION_RELEASE, 1, 2, 0)

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
