
// Yara4Ida plugin main
#include "stdafx.h"
#include "MainDialog.h"

#ifndef _DEBUG
#pragma comment(lib, "libyara/Release/libyara64.lib")
#else
#pragma comment(lib, "libyara/Debug/libyara64.lib")
#endif

#define DEFAULT_RULES_FOLDER L"yara4ida_rules\\default.yar"
#define DEFAULT_SHORTCUT "Alt-Y"
#define COMMENT_TAG "#YARA: "

static plugmod_t* idaapi init();
static void idaapi term();
static bool idaapi run(size_t);
extern BOOL ScanSegments(__out MATCHES& matches);
LPCSTR YaraStatusString(int error);

BOOL optionPlaceComments = TRUE;
BOOL optionSingleThread  = FALSE;
BOOL optionVerbose = FALSE;
//
static WCHAR rulesPath[MAX_PATH] = { 0 };
static char basePath[MAX_PATH] = { 0 };
static char lastRulesFile[MAX_PATH] = { 0 };
static BOOL listChooserUp = FALSE;
static BOOL initResourcesOnce = FALSE;
static int chooserIcon = 0;

// YARA and other data that must be persistent while chooser control is up
static int yaraInitalized = -1;
static YR_COMPILER *s_compiler = NULL;
YR_RULES *g_rules = NULL;
static MATCHES matches;
static std::map<segment_t*, qstring> seg2name;

// ------------------------------------------------------------------------------------------------

// Plug-in description block
__declspec(dllexport) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC,
	init,
	term,
	run,
	"Yara4Ida: (\"Yara for IDA\"). Yara: \"The pattern matching swiss knife\". Unofficial YARA IDA plugin.",
	" ",
	"Yara4Ida",
	DEFAULT_SHORTCUT
};

static plugmod_t* idaapi init()
{
	return PLUGIN_KEEP; // PLUGIN_OK
}

// Normally doesn't hit as we need to stay resident for the modal windows
static void idaapi term()
{
	try
	{
		if (g_rules)
		{
			yr_rules_destroy(g_rules);
			g_rules = NULL;
		}

		if (s_compiler)
		{
			yr_compiler_destroy(s_compiler);
			s_compiler = NULL;
		}

		if (yaraInitalized == ERROR_SUCCESS)
		{
			yr_finalize();
			yaraInitalized = -1;
		}

		matches.clear();
		seg2name.clear();
		listChooserUp = FALSE;

		if (initResourcesOnce)
		{
			if (chooserIcon)
			{
				free_custom_icon(chooserIcon);
				chooserIcon = 0;
			}

			Q_CLEANUP_RESOURCE(PlugInRes);
			initResourcesOnce = FALSE;
		}
	}
	CATCH()
}

// ------------------------------------------------------------------------------------------------

// Rules match IDA chooser/list view
class MatchChooser : public chooser_multi_t
{
	enum COLUMNS
	{
		COL_ADDRESS,
		COL_DESCRIPTION,
		COL_TAGS,
		COL_FILE,

		COL_COUNT
	};

	static int _widths[COL_COUNT];
	static const char *_header[COL_COUNT];
	static const char _title[];

public:
	MatchChooser() : chooser_multi_t(CH_QFTYP_DEFAULT, _countof(_header), _widths, _header, _title)
	{
		seg2name.clear();

		// Setup hex address display to the minimal length plus a leading zero
		ea_t maxAddress = 0;
		size_t maxSegStr = 0;

		for (MATCH& m : matches)
		{
			if (m.address > maxAddress)
				maxAddress = m.address;

			if (segment_t* seg = getseg(m.address))
			{
				qstring name;
				get_segm_name(&name, seg);
				seg2name.try_emplace(seg, name);

				if (name.size() > maxSegStr)
					maxSegStr = name.size();
			}
		}

		char buffer[32];
		size_t digits = strlen(_ui64toa((UINT64)maxAddress, buffer, 16));
		if (++digits > 16) digits = 16;
		sprintf_s(addressFormat, sizeof(addressFormat), "%%s:%%0%ullX", (UINT32)digits);

		// Custom chooser icon
		icon = chooserIcon;
	}

	virtual void closed()
	{
		// Clean up
		term();
	}

	virtual const void* get_obj_id(size_t *len) const
	{
		*len = strlen(title);
		return title;
	}

	virtual size_t get_count() const { return matches.size(); }

	// On row clicked or enter pressed
	virtual cbres_t enter(sizevec_t* sel)
	{
		size_t n = sel->front();
		if (n < get_count())
			jumpto(matches[n].address);
		return NOTHING_CHANGED;
	}

	// Generate a row info
	virtual void get_row(qstrvec_t *cols_, int *icon_, chooser_item_attrs_t *attributes, size_t n) const
	{
		try
		{
			qstrvec_t &cols = *cols_;
			MATCH &m = matches[n];

			LPCSTR name;
			segment_t *seg = getseg(m.address);
			if (seg && (seg2name.find(seg) != seg2name.end()))
				name = seg2name[seg].c_str();
			else
				name = "?????";

			cols[COL_ADDRESS].sprnt(addressFormat, name, (UINT64)m.address);

			// Get description string if rule has one
			BOOL gotDescription = FALSE;
			YR_META *meta;
			yr_rule_metas_foreach(m.rule, meta)
			{
				if ((meta->type == META_TYPE_STRING) && (meta->identifier))
				{
					if (strcmp(meta->identifier, "description") == 0)
					{
						if (meta->string)
						{
							cols[COL_DESCRIPTION] = meta->string;
							gotDescription = TRUE;
						}
						break;
					}
				}
			}

			// Use rule name if there's no description
			if (!gotDescription)
				cols[COL_DESCRIPTION] = ((m.rule->identifier != NULL) ? m.rule->identifier : "?????");

			qstring tags;
			LPCSTR tag_name;
			yr_rule_tags_foreach(m.rule, tag_name)
			{
				tags += tag_name;
				tags += ' ';
			}
			cols[COL_TAGS] = tags;

			cols[COL_FILE] = ((m.rule->ns && m.rule->ns->name) ? m.rule->ns->name : "?????");
			*icon_ = -1;
		}
		CATCH()
	}

private:
	char addressFormat[16];
};

const char MatchChooser::_title[] = { "{ YARA Matches }" };
const char* MatchChooser::_header[COL_COUNT] = { "Address",	"Description", "Tags", "File" };
int MatchChooser::_widths[COL_COUNT] = { /*Address*/ 12, /*Description*/ 40, /*Tags*/ 8, /*File. Auto-extends to the end*/ 20 };

// ------------------------------------------------------------------------------------------------

// YARA compile warnings and error callback
static void YaraCompilerStatusCallback(int error_level, __in const char *file_name, int line_number, __in const YR_RULE *rule, __in const char *message, __in void *user_data)
{
	try
	{
		switch (error_level)
		{
			case YARA_ERROR_LEVEL_ERROR:
			{
				// On return from this error, the compiler will abort
				msg("\n ** Rule compile ERROR: **\n");
				*((LPBOOL) user_data) = TRUE;
			}
			break;

			case YARA_ERROR_LEVEL_WARNING:
			{
				if (!optionVerbose)
					return;

				msg("\n Rule compile WARNING:\n");
			}
			break;
		};

		msg(" File: \"%s\", line: %d\n", file_name, line_number);
		if (rule && rule->metas && rule->metas->identifier)
			msg(" Desc: \"%s\"\n", rule->metas->identifier);
		msg(" Reason: \"%s\"\n", message);
		REFRESH_UI();
	}
	catch (std::exception &ex)
	{
		msg("** STD C++ exception!: What: \"%s\", Function: \"%s\" **\n", ex.what(), __FUNCTION__);
		*((LPBOOL) user_data) = TRUE;
	} 
	catch (...)
	{
		msg("** C/C++ exception! Function: \"%s\" **\n", __FUNCTION__); 
		*((LPBOOL) user_data) = TRUE;
	}
}

// YARA compile include file callback
static const char* YaraCompilerIncludesCallback(__in const char *include_name, __in const char *calling_rule_filename, __in const char *calling_rule_namespace, __in void *user_data)
{
	// Need this for two reasons: 
	//  1) To resolve relative paths for "include" directive files.
	//  2) Verbose log/msg output for showing the inclusion of "include" directive files.
	BOOL success = FALSE;
	FILE *fp = NULL;
	LPSTR fileBuffer = NULL;

	try
	{
		if (optionVerbose)
			//msg(" Include: \"%s\", Calling rule: \"%s\", \"%s\"\n", include_name, calling_rule_filename, calling_rule_namespace);
			msg(" Include: Path: \"%s\", Calling rule: \"%s\"\n", include_name, calling_rule_filename);

		// Convert the usual relative to absolute path as needed
		char fixedPath[MAX_PATH];
		if (PathIsRelativeA(include_name))
		{
			// Combine with base path derived from the root input file
			char combinedPath[MAX_PATH] = { 0 };
			if (!PathCombineA(combinedPath, basePath, include_name))
			{
				msg("YaraCompilerIncludesCallback: ** Failed to combine paths! **\n");
				return NULL;
			}

			// Clean up combined path
			GetFullPathNameA(combinedPath, sizeof(fixedPath), fixedPath, NULL);
			include_name = fixedPath;
		}

		// Read the text file into a buffer and return it
		qwstring includePath;
		utf8_utf16(&includePath, include_name);
		errno_t err = _wfopen_s(&fp, includePath.c_str(), L"rbS");
		if (err != 0)
			goto exit;

		long fileSize = fsize(fp);
		if (fileSize == -1)
			goto exit;

		fileBuffer = (LPSTR) _aligned_malloc((size_t)fileSize + 1, 32);
		if (!fileBuffer)
			goto exit;

		success = (fread(fileBuffer, (size_t)fileSize, 1, fp) == 1);
		fileBuffer[fileSize] = 0;
	}
	CATCH()

	exit:;
	if (fp)
	{
		fclose(fp);
		fp = NULL;
	}
	if (success)
		return fileBuffer;
	else
	{
		_aligned_free(fileBuffer);
		fileBuffer = NULL;
		return NULL;
	}
}
//
static void YaraCompilerIncludesFree(__in const char *callback_result_ptr, __in void *user_data)
{
	_aligned_free((PVOID) callback_result_ptr);
}

// ------------------------------------------------------------------------------------------------

void AltFileBtnHandler()
{
	if (LPSTR sigPathUtf8 = ask_file(FALSE, "*.yar;*.yara;*.rules", "Yara4Ida: Select YARA rules file"))
	{
		// From UTF-8 to WCHAR'ish
		qwstring tmp;
		utf8_utf16(&tmp, sigPathUtf8);
		wcsncpy_s(rulesPath, MAX_PATH, tmp.c_str(), tmp.size());
	}
}

static bool idaapi run(size_t arg)
{
	// Don't run again while our chooser is already up
	if (listChooserUp)
	{
		PlaySound((LPCSTR) SND_ALIAS_SYSTEMEXCLAMATION, NULL, (SND_ALIAS_ID | SND_ASYNC));
		return true;
	}

	BOOL success = FALSE;
	BOOL compileError = FALSE;
	FILE *fp = NULL;

	try
	{
		qstring version, tmp;
		version.sprnt("v%s, built %s", GetVersionString(MY_VERSION, tmp).c_str(), __DATE__);
		msg("\n>> " MSG_TAG "%s\n", version.c_str());
		REFRESH_UI();

		if (!auto_is_ok())
		{
			msg(MSG_TAG "* Please wait for IDA analysis to complete first!, Aborted *\n");
			goto exit;
		}
		
		// Get the default relative to the IDA plugin rules file path
		HMODULE myModule = NULL;
		GetModuleHandleExA((GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS), (LPCTSTR) &run, &myModule);
		GetModuleFileNameExW(GetCurrentProcess(), myModule, rulesPath, SIZESTR(rulesPath));
		PathRemoveFileSpecW(rulesPath);
		wcscat(rulesPath, L"\\" DEFAULT_RULES_FOLDER);

		// Configure platform specifics
		plat.Configure();

		if (!initResourcesOnce)
		{
			initResourcesOnce = TRUE;
			Q_INIT_RESOURCE(PlugInRes);

			QFile file(STYLE_PATH "icon.png");
			if (file.open(QFile::ReadOnly))
			{
				QByteArray ba = file.readAll();
				chooserIcon = load_custom_icon(ba.constData(), ba.size(), "png");
			}
		}
			
		// -------------------------------------------
		// 1) Do main dialog		
		if (doMainDialog(optionPlaceComments, optionSingleThread, optionVerbose))
		{
			msg("- Canceled -\n\n");
			success = TRUE;
			return true;
		}

		// -------------------------------------------
		// 2) Initialize libyara and open the rules file
		WaitBox::show("Yara for IDA", "Scanning..", "url(" STYLE_PATH "progress-style.qss)", STYLE_PATH "icon.png");
		WaitBox::updateAndCancelCheck(-1);
		REFRESH_UI();

		char numBuff[32];
		TIMESTAMP startTime = GetTimeStamp();
		yaraInitalized = yr_initialize();
		if (yaraInitalized != ERROR_SUCCESS)
		{
			msg(MSG_TAG "** YARA yr_initialize() failed with: %s **\n", YaraStatusString(yaraInitalized));
			goto exit;
		}

		// Create compiler object
		int yaraResult = yr_compiler_create(&s_compiler);
		if (yaraResult != ERROR_SUCCESS)
		{
			msg(MSG_TAG "** YARA yr_compiler_create() failed with: %s **\n", YaraStatusString(yaraResult));
			goto exit;
		}
		yr_compiler_set_callback(s_compiler, YaraCompilerStatusCallback, &compileError);
		yr_compiler_set_include_callback(s_compiler, YaraCompilerIncludesCallback, YaraCompilerIncludesFree, NULL);
		//msg("yr_compiler_create time: %s\n", TimestampString(GetTimestamp() - startTime, buffer2));

		// Open rules file
		qstring utf8Path;
		utf16_utf8(&utf8Path, rulesPath);
		strncpy_s(lastRulesFile, sizeof(lastRulesFile), utf8Path.c_str(), SIZESTR(lastRulesFile));
		strncpy_s(basePath, sizeof(basePath), utf8Path.c_str(), SIZESTR(basePath) - 1);
		if (LPSTR filename = PathFindFileNameA(basePath))
			*filename = 0;
		msg("Loading rules from: \"%s\"\n", lastRulesFile);
		REFRESH_UI();
		errno_t err = _wfopen_s(&fp, rulesPath, L"rbS");
		if (err != 0)
		{
			char buffer[1024];
			strerror_s(buffer, sizeof(buffer), err);
			msg(MSG_TAG "** Rules open failed with: \"%s\" **\n", buffer);
			goto exit;
		}

		// -------------------------------------------
		// 3) Compile rules from rules file by handle
		yaraResult = yr_compiler_add_file(s_compiler, fp, utf8Path.c_str(), utf8Path.c_str());
		if (compileError)
		{
			// If compile error, bail out here since the yaraResult usually doesn't match the error				
			goto exit;
		}
		else
		if (yaraResult != ERROR_SUCCESS)
		{
			msg(MSG_TAG "** YARA yr_compiler_add_file() failed with: %s **\n", YaraStatusString(yaraResult));
			goto exit;
		}

		fclose(fp);
		fp = NULL;

		// Get a rule set ref from the compiler instance
		yaraResult = yr_compiler_get_rules(s_compiler, &g_rules);
		if (yaraResult != ERROR_SUCCESS)
		{
			msg(MSG_TAG "** YARA yr_compiler_get_rules() failed with: %s **\n", YaraStatusString(yaraResult));
			goto exit;
		}
		msg("%s rules loaded in %s\n", NumberCommaString(g_rules->num_rules, numBuff), TimeString(GetTimeStamp() - startTime));
		if (g_rules->num_rules == 0)
		{
			msg("* No rules loaded, aborted *\n");
			goto exit;
		}
		REFRESH_UI();

		// -------------------------------------------
		// 4) Scan segments with compiled YARA rules			
		if (ScanSegments(matches))
		{
			// On user abort or failure
			success = FALSE;
			goto exit;
		}

		// -------------------------------------------
		// 5) Optionally place comments, and show a match result IDA chooser
		if (!matches.empty())
		{
			if (optionPlaceComments)
			{
				for (MATCH &m : matches)
				{
					// Snap address to nearest item address
					ea_t address = get_item_head(m.address);

					// Already has comment?
					qstring comment;
					int size = (int) get_cmt(&comment, address, TRUE);
					if (size > 0)
					{
						// Yes. Skip if already has a comment from us from a previous run
						if ((size > sizeof(COMMENT_TAG)) && (comment.find(COMMENT_TAG) != qstring::npos))
							size = -1;
						if (size != -1)
						{
							// If large string add a line break else use a space to separate them
							if (size >= 54)
							{
								comment.append('\n');
								size += SIZESTR("\n");
							}
							else
							{
								comment.append(' ');
								size += SIZESTR(" ");
							}
						}
					}
					else
						size = 0;

					if (size >= 0)
					{
						// Get description string if rule has one
						LPCSTR description = NULL;
						YR_META *meta;
						yr_rule_metas_foreach(m.rule, meta)
						{
							if ((meta->type == META_TYPE_STRING) && (meta->identifier))
							{
								if (strcmp(meta->identifier, "description") == 0)
								{
									if (meta->string)
										description = meta->string;
									break;
								}
							}
						}

						// If no description use rule name
						if (!description || !description[0])
							description = ((m.rule->identifier != NULL) ? m.rule->identifier : "????");

						char buffer[MAXSTR];
						if (comment.empty())
							_snprintf_s(buffer, sizeof(buffer), SIZESTR(buffer), COMMENT_TAG "\"%s\" ", description);
						else
							_snprintf_s(buffer, sizeof(buffer), SIZESTR(buffer), "%s" COMMENT_TAG "\"%s\" ", comment.c_str(), description);
						set_cmt(address, buffer, TRUE);
					}
				}
			}

			// Show the match chooser
			//if (iconID == -1)
			//	iconID = load_custom_icon(iconData, sizeof(iconData), "png");
			MatchChooser *chooser = new MatchChooser();
			success = listChooserUp = (chooser && (chooser->choose() == 0));
			msg(MSG_TAG "Found %s matches in %s\n", NumberCommaString(matches.size(), numBuff), TimeString(GetTimeStamp() - startTime));
		}
		else
		{
			msg("Done. No rule matches found.\n");
			goto exit;
		}
	}
	CATCH()

	exit:;
	if (fp)
	{
		fclose(fp);
		fp = NULL;
	}
	if (!success)
	{
		// Clean up YARA data on abort or failure
		msg("* Aborted *\n");
		//term();
	}
	if (optionPlaceComments)
		refresh_idaview_anyway();

	WaitBox::hide();
	REFRESH_UI();
	return TRUE;
}

// ------------------------------------------------------------------------------------------------

// In the libyara source there's a "yr_debug_error_as_string()", but not exposed from the library
LPCSTR YaraStatusString(int error)
{
	if ((error >= ERROR_SUCCESS) && (error <= ERROR_IDENTIFIER_MATCHES_WILDCARD))
	{
		const char* strings[] =
		{
			"ERROR_SUCCESS",                        // 0
			"ERROR_INSUFFICIENT_MEMORY",            // 1 
			"ERROR_COULD_NOT_ATTACH_TO_PROCESS",	// 2 
			"ERROR_COULD_NOT_OPEN_FILE",			// 3 
			"ERROR_COULD_NOT_MAP_FILE",				// 4 
			"ERROR_INVALID_FILE",					// 6 
			"ERROR_CORRUPT_FILE",					// 7 
			"ERROR_UNSUPPORTED_FILE_VERSION",		// 8 
			"ERROR_INVALID_REGULAR_EXPRESSION",		// 9 
			"ERROR_INVALID_HEX_STRING",				// 10
			"ERROR_SYNTAX_ERROR",					// 11
			"ERROR_LOOP_NESTING_LIMIT_EXCEEDED",	// 12
			"ERROR_DUPLICATED_LOOP_IDENTIFIER",		// 13
			"ERROR_DUPLICATED_IDENTIFIER",			// 14
			"ERROR_DUPLICATED_TAG_IDENTIFIER",		// 15
			"ERROR_DUPLICATED_META_IDENTIFIER",		// 16
			"ERROR_DUPLICATED_STRING_IDENTIFIER",	// 17
			"ERROR_UNREFERENCED_STRING",			// 18
			"ERROR_UNDEFINED_STRING",				// 19
			"ERROR_UNDEFINED_IDENTIFIER",			// 20
			"ERROR_MISPLACED_ANONYMOUS_STRING",		// 21
			"ERROR_INCLUDES_CIRCULAR_REFERENCE",	// 22
			"ERROR_INCLUDE_DEPTH_EXCEEDED",			// 23
			"ERROR_WRONG_TYPE",						// 24
			"ERROR_EXEC_STACK_OVERFLOW",			// 25
			"ERROR_SCAN_TIMEOUT",					// 26
			"ERROR_TOO_MANY_SCAN_THREADS",			// 27
			"ERROR_CALLBACK_ERROR",					// 28
			"ERROR_INVALID_ARGUMENT",				// 29
			"ERROR_TOO_MANY_MATCHES",				// 30
			"ERROR_INTERNAL_FATAL_ERROR",			// 31
			"ERROR_NESTED_FOR_OF_LOOP",				// 32
			"ERROR_INVALID_FIELD_NAME",				// 33
			"ERROR_UNKNOWN_MODULE",					// 34
			"ERROR_NOT_A_STRUCTURE",				// 35
			"ERROR_NOT_INDEXABLE",					// 36
			"ERROR_NOT_A_FUNCTION",					// 37
			"ERROR_INVALID_FORMAT",					// 38
			"ERROR_TOO_MANY_ARGUMENTS",				// 39
			"ERROR_WRONG_ARGUMENTS",				// 40
			"ERROR_WRONG_RETURN_TYPE",				// 41
			"ERROR_DUPLICATED_STRUCTURE_MEMBER",	// 42
			"ERROR_EMPTY_STRING",					// 43
			"ERROR_DIVISION_BY_ZERO",				// 44
			"ERROR_REGULAR_EXPRESSION_TOO_LARGE",	// 45
			"ERROR_TOO_MANY_RE_FIBERS",				// 46
			"ERROR_COULD_NOT_READ_PROCESS_MEMORY",	// 47
			"ERROR_INVALID_EXTERNAL_VARIABLE_TYPE",	// 48
			"ERROR_REGULAR_EXPRESSION_TOO_COMPLEX", // 49
			"ERROR_INVALID_MODULE_NAME",			// 50
			"ERROR_TOO_MANY_STRINGS",				// 51
			"ERROR_INTEGER_OVERFLOW",				// 52
			"ERROR_CALLBACK_REQUIRED",				// 53
			"ERROR_INVALID_OPERAND",				// 54
			"ERROR_COULD_NOT_READ_FILE",			// 55
			"ERROR_DUPLICATED_EXTERNAL_VARIABLE",	// 56
			"ERROR_INVALID_MODULE_DATA",			// 57
			"ERROR_WRITING_FILE",					// 58
			"ERROR_INVALID_MODIFIER",				// 59
			"ERROR_DUPLICATED_MODIFIER",			// 60
			"ERROR_BLOCK_NOT_READY",				// 61
			"ERROR_INVALID_PERCENTAGE",				// 62
			"ERROR_IDENTIFIER_MATCHES_WILDCARD"		// 63
		};
		return strings[error];
	}
	else
		return "UNKNOWN";
}
