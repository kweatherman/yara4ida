
// Yara4Ida segment scanning
#include "StdAfx.h"
#include "ConcurrentCallbacks.h"

extern BOOL optionPlaceComments, optionSingleThread, optionVerbose;
extern YR_RULES *g_rules;
extern LPCSTR YaraStatusString(int error);

// Segment scan container
struct SEGMENT
{
	segment_t *seg;
	std::vector<BYTE> buffer;
	std::vector<MATCH> matches;
	qstrvec_t messages;
	int cbResult;

	// Called from the IDA thread only
	SEGMENT(__in segment_t *_seg) : cbResult(ERROR_CALLBACK_ERROR)
	{
		seg = _seg;		

		// Clone the segment bytes into our buffer
		size_t segSize = seg->size();
		buffer.resize(segSize);
		buffer.reserve(segSize);

		// Simple loop much faster than: get_qword(), get_bytes(), etc.
		// Note: For bytes that don't exist in the PE file, get_db_byte() will return 0xFF.
		ea_t  ea = seg->start_ea;
		PBYTE ptr = buffer.data();

		do
		{
			*ptr = get_db_byte(ea);
			++ea, ++ptr, --segSize;
		} while (segSize);
	}

	// Queue message up for later print from the IDA thread
	void qmsg(LPCSTR format, ...)
	{
		qstring qs;
		va_list va;		
		va_start(va, format);				
		qs.vsprnt(format, va);
		va_end(va);
		messages.push_back(qs);
	}

	// Dump messages from IDA thread
	void DumpQueuedMessages()
	{
		for (qstring &qs: messages)		
			msg(qs.c_str());	
	}
};


// YARA rule scan callback
// Note: Not guaranteed to be IDA thread, call no IDA API functions in here
static int YaraScanCallback(__in YR_SCAN_CONTEXT *context, int message, __in void *message_data, __in void *user_data)
{
	SEGMENT *seg = (SEGMENT*) user_data;

	try
	{		
		switch (message)
		{
			case CALLBACK_MSG_RULE_MATCHING:
			{		
				YR_RULE *rule = (YR_RULE*) message_data;
				//seg->qmsg("\n Rule: \"%s\"\n", rule->identifier);
				
				YR_STRING *str;
				yr_rule_strings_foreach(rule, str)
				{
					//seg->qmsg("  Str: \"%s\"\n", str->identifier);
					YR_MATCH *match;
					yr_string_matches_foreach(context, str, match)
					{					
						//seg->qmsg("   Match: offset: 0x%llX\n", match->offset);
						seg->matches.push_back({ rule, seg->seg->start_ea + (ea_t) match->offset });
					}
				}			
			}
			break;

			case CALLBACK_MSG_TOO_MANY_MATCHES:
			{		
				// The default YR_MAX_STRING_MATCHES = 1000000				
				YR_STRING *str = (YR_STRING*) message_data;		
				YR_RULE *rule = &context->rules->rules_table[str->rule_idx];
				//seg->qmsg("* Warning: Rule \"%s\" has too many matches for \"%s\" *\n", rule->identifier, str->identifier);
				seg->qmsg("* Warning: Rule \"%s\" exceeded max match count *\n", rule->identifier);
			}
			break;

			case CALLBACK_MSG_CONSOLE_LOG:
			{
				if (optionVerbose)				
					seg->qmsg("Console: \"%s\"\n", message_data);				
			}
			break;
		};
	}
	catch (std::exception &ex)
	{
		if (seg) seg->qmsg("YaraScanCallback(): ** C++ exception: \"%s\" **\n", ex.what());
		return CALLBACK_ERROR;
	}
	catch (...)
	{
		if (seg) seg->qmsg("YaraScanCallback(): ** General C exception **\n");
		return CALLBACK_ERROR;
	}

	return CALLBACK_CONTINUE;
}

static BOOL SegmentScanWorker(__in PVOID lParm)
{
	//trace("SW start TID: %08X, core: %u\n", GetCurrentThreadId(), GetCurrentProcessorNumber());
	SEGMENT &seg = *((SEGMENT*) lParm);
	seg.cbResult = yr_rules_scan_mem(g_rules, seg.buffer.data(), seg.buffer.size(), SCAN_FLAGS_REPORT_RULES_MATCHING, YaraScanCallback, &seg, 0);
	//trace("SW done TID: %08X, core: %u\n", GetCurrentThreadId(), GetCurrentProcessorNumber());
	return seg.cbResult != ERROR_SUCCESS;	
}

// YARA scan IDB memory segments, called from IDA thread
// Returns TRUE if user aborted or on error
BOOL ScanSegments(__out MATCHES &matches)
{
	BOOL aborted = TRUE;	
	std::list<SEGMENT> segments;
	ConcurrentCallbackGroup *ccg = NULL;

	#define TRY_UPDATE_CANCEL() \
		if (WaitBox::isUpdateTime()) \
		{ \
			if (WaitBox::updateAndCancelCheck()) \
			{ \
				aborted = TRUE; \
				goto exit; \
			} \
		}

	try
	{
		UINT32 scanThreads = optionSingleThread ? 1 : 0;
		if (scanThreads != 1)
			scanThreads = ConcurrentCallbackGroup::GetLogicalCoreCount();
		if(scanThreads == 1)
			msg("\n" MSG_TAG "Using single threaded scanning.\n");
		else
			msg("\n" MSG_TAG "Using up to %u logical core threads for scanning.\n", scanThreads);
		
		// Instance the callback manager
		HRESULT hr = E_FAIL;
		ccg = new ConcurrentCallbackGroup(hr, scanThreads);
		if (!ccg || (hr != ERROR_SUCCESS))
		{
			char buffer[1024];
			msg("** ConcurrentCallbackGroup() create failed! Reason: \"%s\" **\n", GetLastErrorString(hr, buffer));
			goto exit;
		}		

		msg("Walking segments:\n");
		REFRESH_UI();
		matches.clear();		

		// 1) Add segments to scan
		int count = get_segm_qty();
		for (int i = 0; i < count; i++)
		{
			if (segment_t *seg = getnseg(i))
			{
				qstring name;
				get_segm_name(&name, seg);
				qstring classStr;
				get_segm_class(&classStr, seg);

				switch (seg->type)
				{
					// Types to skip
					case SEG_XTRN:
					case SEG_GRP:
					case SEG_NULL:
					case SEG_UNDF:
					case SEG_ABSSYM:
					case SEG_COMM:
					case SEG_IMEM:
					{
						//msg(MSG_TAG "Skip segment: \"%s\", \"%s\", %d, " EAFORMAT " - " EAFORMAT ", %s\n", name.c_str(), classStr.c_str(), seg->type, seg->start_ea, seg->end_ea, byteSizeString(seg->size()));
						//REFRESH_UI();							
					}
					break;

					default:
					{
						char buffer[32];
						msg(" \"%s\", %s, " EAFORMAT " - " EAFORMAT ", %s\n", name.c_str(), classStr.c_str(), seg->start_ea, seg->end_ea, ByteSizeString(seg->size(), buffer));
						REFRESH_UI();
						if (seg->size() > 0)
						{
							// Mirror segment bytes
							segments.push_back({ seg });
							SEGMENT *sp = &segments.back();

							// Start up scanning on this segment's data
							// Depending on the thread pool size will either start now or will be queued for later
							HRESULT hr = ccg->Add(SegmentScanWorker, sp, TRUE);
							if (hr != ERROR_SUCCESS)
							{
								char buffer[1024];
								msg("** ConcurrentCallbackGroup::Add() failed! Reason: \"%s\" **\n", GetLastErrorString(hr, buffer));
								goto exit;
							}
							else
							{
								TRY_UPDATE_CANCEL();
							}
						}
					}
					break;
				};
			}
		}

		// 2) Wait for segment scans to complete..
		msg("\nScanning:\n");
		REFRESH_UI();

		Sleep(50);
		long errorCount = 0;		
		do
		{			
			// Update wait box periodically, checking if "Cancel" button was pressed
			TRY_UPDATE_CANCEL();

			Sleep(50);
			hr = ccg->Poll(errorCount);

		} while (hr == E_PENDING);

		// Scan jobs completed
		if (hr != ERROR_SUCCESS)
		{
			char buffer[1024];
			msg("** ConcurrentCallbackGroup::Poll() scanning failed! HR: 0x%X \"%s\", Total errors: %d **\n", hr, GetLastErrorString(hr, buffer), errorCount);
			goto exit;
		}
		
		// Even if we got an error(s) waiting, first dump out the queued messages which should have the logged 
		// errors in it.
		UINT32 index = 0;
		for (SEGMENT &seg: segments)
		{				
			qstring name;
			get_segm_name(&name, seg.seg);
			msg(" [%u] \"%s\"", index++, name.c_str());
			if (seg.cbResult != ERROR_SUCCESS)
				msg(" ** Error: %s **\n", YaraStatusString(seg.cbResult));
			if (seg.matches.empty())
				msg("\n");
			else
			{
				char buffer[32];
				msg(", %s matches\n", NumberCommaString(seg.matches.size(), buffer));
				REFRESH_UI();
				matches.insert(std::end(matches), std::begin(seg.matches), std::end(seg.matches));
			}

			// Dump queued scanning messages
			if (!seg.messages.empty())
			{
				seg.DumpQueuedMessages();
				msg(" \n");
			}
			REFRESH_UI();
		}

		WaitBox::updateAndCancelCheck();
		if ((hr == ERROR_SUCCESS) && (errorCount == 0))
			aborted = FALSE;
		else
		{
			// Now report if there was a scan error
			char buffer[1024];
			msg(MSG_TAG "** YARA scan failed! Reason: \"%s\", errors: %d **\n", GetLastErrorString(hr, buffer), errorCount);
			REFRESH_UI();
		}		

		msg("\n");
		aborted = FALSE;
	}
	catch (std::exception& ex)
	{
		msg("ScanSegments(): ** C++ exception: \"%s\" **\n", ex.what());
		aborted = TRUE;
	}
	catch (...)
	{
		msg("ScanSegments(): ** General C exception **\n");
		aborted = TRUE;
	}

	exit:;	
	if (aborted)	
		matches.clear();			
	else
	{
		matches.reserve(matches.size());
		std::sort(matches.begin(), matches.end(), MATCH());
		WaitBox::updateAndCancelCheck();
	}
	if (ccg)
	{
		if (optionVerbose)		
			msg("Destructing ConcurrentCallbackGroup object.\n");		
		delete ccg;
		ccg = NULL;
	}
	
	REFRESH_UI();
	return aborted;
}
