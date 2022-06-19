
// IDA plugin utility support
#include "StdAfx.h"
#include <tchar.h>
#include <winnt.h>
#include <tlhelp32.h>

static ALIGN(16) TIMESTAMP performanceFrequency = 0;
struct OnUtilityInit
{
	OnUtilityInit()
	{
		LARGE_INTEGER large;
		QueryPerformanceFrequency(&large);
		performanceFrequency = (TIMESTAMP) large.QuadPart;
	}
} static utilityInit;


// Build a string from our 32bit semantic versioning format
qstring &GetVersionString(UINT32 version, __out qstring &version_string)
{
	version_string.sprnt("%u.%u.%u", GET_VERSION_MAJOR(MY_VERSION), GET_VERSION_MINOR(MY_VERSION), GET_VERSION_PATCH(MY_VERSION));
	VERSION_STAGE stage = GET_VERSION_STAGE(version);
	switch (GET_VERSION_STAGE(version))
	{
		case VERSION_ALPHA:	version_string += "-alpha";	break;
		case VERSION_BETA: version_string += "-beta"; break;
	};
	return version_string;
}

// Output formated text to debugger channel
void trace(LPCSTR format, ...)
{
	if (format)
	{
		va_list vl;
		// The OS buffer for these messages is a page/4096 size max
		char buffer[4096];
		va_start(vl, format);
		_vsntprintf_s(buffer, sizeof(buffer), SIZESTR(buffer), format, vl);
		va_end(vl);
		OutputDebugString(buffer);
	}
}


// Return high resolution elapsed float seconds
TIMESTAMP GetTimestamp()
{
	LARGE_INTEGER large;
	QueryPerformanceCounter(&large);
	return ((TIMESTAMP) large.QuadPart / performanceFrequency);
}

// Make a pretty time string from a timestamp
LPSTR TimestampString(TIMESTAMP time, __out_bcount_z(64) LPSTR buffer)
{
	if(time >= HOUR)
		sprintf_s(buffer, 64, "%.2f hours", (time / (TIMESTAMP) HOUR));
	else
	if(time >= MINUTE)
		sprintf_s(buffer, 64, "%.2f minutes", (time / (TIMESTAMP) MINUTE));
	else
	if(time < (TIMESTAMP) 0.5)
		sprintf_s(buffer, 64, "%.1fms", (time * (TIMESTAMP) 1000.0));
	else
		sprintf_s(buffer, 64, "%.2f seconds", time);
	return buffer;
}

// Make a pretty comma separated unsigned decimal value string
LPSTR NumberCommaString(UINT64 n, __out_bcount_z(32) LPSTR buffer)
{
	int i = 0, c = 0;
	do
	{
		buffer[i] = ('0' + (n % 10)); i++;

		n /= 10;
		if ((c += (3 && n)) >= 3)
		{
			buffer[i] = ','; i++;
			c = 0;
		}

	} while (n);
	buffer[i] = 0;
	return _strrev(buffer);
}

// Returns a pretty factional byte size string for given input size
LPSTR ByteSizeString(UINT64 bytesSize, __out_bcount_z(32) LPSTR buffer)
{
    const UINT64 KILLOBYTE = 1024;
    const UINT64 MEGABYTE = (KILLOBYTE * 1024); // 1048576
    const UINT64 GIGABYTE = (MEGABYTE * 1024);  // 1073741824
    const UINT64 TERABYTE = (GIGABYTE * 1024);  // 1099511627776

    #define BYTESTR(_Size, _Suffix) \
    { \
		double floatSize = ((double) bytesSize / (double) _Size); \
		double integral; double fFractional = modf(floatSize, &integral); \
		if(fFractional > 0.05) \
			sprintf_s(buffer, 32, ("%.1f " ## _Suffix), floatSize); \
	    else \
			sprintf_s(buffer, 32, ("%.0f " ## _Suffix), integral); \
    }
    
    ZeroMemory(buffer, 32);
    if (bytesSize >= TERABYTE)
        BYTESTR(TERABYTE, "TB")
    else
    if (bytesSize >= GIGABYTE)
        BYTESTR(GIGABYTE, "GB")
    else
    if (bytesSize >= MEGABYTE)
        BYTESTR(MEGABYTE, "MB")
    else
    if (bytesSize >= KILLOBYTE)
        BYTESTR(KILLOBYTE, "KB")
    else
		sprintf_s(buffer, 32, "%u byte%c", (UINT) bytesSize, (bytesSize == 1) ? 0 : 's');
    return buffer;
}

// Get an error string for a GetLastError() code
LPSTR GetLastErrorString(DWORD lastError, __out_bcount_z(1024) LPSTR buffer)
{
	if (!FormatMessageA((FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS),
		NULL, lastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buffer, 1024, NULL))
	{
		strncpy_s(buffer, 1024, "Unknown", (1024 - 1));
	}
	else
	{
		if (LPSTR lineFeed = strstr(buffer, "\r"))
			*lineFeed = 0;
	}
	return buffer;
}


// ------------------------------------------------------------------------------------------------

// Get 32bit file size by file handle
long fsize(__in FILE *fp)
{
	long psave, endpos;
	long result = -1;

	if ((psave = ftell(fp)) != -1L)
	{
		if (fseek(fp, 0, SEEK_END) == 0)
		{
			if ((endpos = ftell(fp)) != -1L)
			{
				fseek(fp, psave, SEEK_SET);
				result = endpos;
			}
		}
	}

	return result;
}

// Dump our threads to track them for development
BOOL DumpProcessThreads()
{
	msg("======== Threads ========\n");
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return FALSE;

	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);
	DWORD pid = GetCurrentProcessId();

	UINT32 i = 0;
	if (Thread32First(hThreadSnap, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == pid)
				msg("[%04u] TID: %08X\n", i++, te32.th32ThreadID);
		} while (Thread32Next(hThreadSnap, &te32));
	}

	CloseHandle(hThreadSnap);
	msg(" \n");
	return TRUE;
}

// Print C SEH info
// useDebug = TRUE: Use the debug channel for output when not in within the IDA thread
int ReportException(__in LPCSTR name, __in LPEXCEPTION_POINTERS nfo, BOOL useDebug)
{
	#define ERROR_FORMAT MSG_TAG "** Exception: 0x%08X @ 0x%llX, in %s()! **\n"	
	if (useDebug)
		trace(ERROR_FORMAT, nfo->ExceptionRecord->ExceptionCode, nfo->ExceptionRecord->ExceptionAddress, name);
	else
		msg(ERROR_FORMAT, nfo->ExceptionRecord->ExceptionCode, nfo->ExceptionRecord->ExceptionAddress, name);
	return EXCEPTION_EXECUTE_HANDLER;
	#undef ERROR_FORMAT
}
