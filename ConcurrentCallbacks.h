
// Concurrent callback support
#pragma once

#include <list>

/*
Minimalist Windows thread pool API object to run simple callbacks concurrently to take advantage
of multiple CPU cores; spreading out work for performance gain.

Instance a "new ConcurrentCallbackGroup" to initialize needed resources (local thread pool and support data),
then "delete ConcurrentCallbackGroup" the object when done to kill callback threads et al.

Intended to be used one of two ways:
1) Queue up all the callbacks first via "Add()" then fire them up all at once using "Start()".
2) Or one at the time add callbacks via "Add()" and either do optional "start = TRUE" argument, or 
call "Start()" imeadiatly after.
In either case, queue/add all the callbacks jobs first and start them up before using either the 
"Wait()" or "Poll()" methods for completion status since these rely on a simple counting mechanism internally.

The WORKER_CALLBACK callbacks should return FALSE for success or TRUE on error.
Pass opaque data to the callbacks via the "PVOID lParm" argument.
It's up to the callback do any atomic operations to be thread safe if external shared resource data are used.

Version: 1.0.0 2/14/2022
Author: Kevin Weatherman
*/
class ConcurrentCallbackGroup
{
public:
	// Callbacks return TRUE to indicate error, else FALSE to signal success
	typedef BOOL (WINAPI* WORKER_CALLBACK)(__in PVOID lParm);

	// Add a new worker callback to the queue
	// Returns HRESULT ERROR_SUCCESS on success else error code on failure
	HRESULT Add(__in ConcurrentCallbackGroup::WORKER_CALLBACK callback, __in PVOID lParm = NULL, BOOL start = FALSE)
	{		
		workers_lock();
			m_workers.push_back({ NULL, FALSE, this, callback, lParm });
			WORKER *wp = &m_workers.back();
		workers_unlock();

		wp->work = CreateThreadpoolWork(CallbackWrapper, wp, &m_callbackEnv);			
		HRESULT hr = (wp->work != NULL) ? ERROR_SUCCESS : HRESULT_FROM_WIN32(GetLastError());

		// Optionally start up the callback(s) now
		if ((m_started || start) && (hr == ERROR_SUCCESS))
		{			
			Start();

			// If not enabled already via the previous Start(), do it now
			if (m_started && (InterlockedCompareExchange((PLONG) &wp->enabled, TRUE, FALSE) == FALSE))
				SubmitThreadpoolWork(wp->work);
		}

		return hr;
	}

	// Start up the parallel callback queue
	// Returns ERROR_SUCCESS on success
	//  On failure our object should be deleted for cleanup
	void Start()
	{		
		if (!m_started)
		{
			m_started = TRUE;

			// Set the pool size max to the CPU logical core count if the user didn't argument override it
			if (m_maxThreads == 0)
			{				
				// TODO: Depending on the workloads, might just want use only physical cores vs using any HT/SMT ones								
				m_maxThreads = GetLogicalCoreCount();
			}			
			
			SetThreadpoolThreadMinimum(m_pool, 0);
			SetThreadpoolThreadMaximum(m_pool, m_maxThreads);

			// Fire up any queued callbacks..
			workers_lock();
			{
				for (WORKER &w: m_workers)
				{
					if (InterlockedCompareExchange((PLONG) &w.enabled, TRUE, FALSE) == FALSE)
						SubmitThreadpoolWork(w.work);
				}
			}
			workers_unlock();			
		}		
	}

	// Wait for started queue callbacks to complete	
	// Returns ERROR_SUCCESS if completed, else returns E_FAIL on errors
	HRESULT Wait(__out long &errorCount)
	{
		if (m_started)
		{
			#ifdef _DEBUG
			// Should be enabled here
			workers_lock();
			{
				for (WORKER &w: m_workers)
				{
					_ASSERT(InterlockedCompareExchange((PLONG) &w.enabled, TRUE, FALSE) == TRUE);				
				}
			}
			workers_unlock();
			#endif

			// Loop until all callbacks have returned or until one errored out
			long queueSize = MAXINT;
			while (!m_workerErrors)
			{
				workers_lock();
					queueSize = (long) m_workers.size();
				workers_unlock();
				if (m_completed >= queueSize)
					break;

				// Give up our caller thread for a while..
				Sleep(50);
			};

			errorCount = m_workerErrors;
			return ((m_workerErrors == 0) && (m_completed >= queueSize)) ? ERROR_SUCCESS : E_FAIL;
		}
		else
		{
			errorCount = 0;
			return E_FAIL;
		}
	}

	// Check if the callback queue has completed
	// Returns ERROR_SUCCESS if completed or E_PENDING if still pending; E_FAIL on error
	HRESULT Poll(__out long &errorCount)
	{
		if (m_started)
		{
			errorCount = m_workerErrors;
			if (errorCount == 0)
			{
				workers_lock();
					long queueSize = (long) m_workers.size();
				workers_unlock();
				return ((m_completed >= queueSize)) ? ERROR_SUCCESS : E_PENDING;
			}
		}
		else
			errorCount = 0;
		return E_FAIL;
	}

	// Abort the running queue for cases where the user requests it, when or app is closing, or when our DLL is unloading.
	// Will block until all active callback threads are done.
	// Same effect as simply destructing our object
	void Abort()
	{
		Cleanup();
	}

	// Return max thread count. Valid after Start() called
	UINT32 MaxTheads()
	{
		if (m_started)
			return m_maxThreads;
		else
			return 0;
	}
	
	// Construct object:
	// initResult = HRESULT initialize result. ERROR_SUCCESS on success, else FAILED status
	// maxThreadCount = Optionally limit the max pool threads to this count, default '0' to use max one thread per logical core.
	ConcurrentCallbackGroup(__out HRESULT &initResult, __in_opt UINT32 maxThreadCount = 0) :
		m_completed(0), m_workerErrors(0), m_started(FALSE), m_pool(NULL), m_cleanupGroup(NULL)
	{
		initResult = E_FAIL;
		m_maxThreads = maxThreadCount;
		ZeroMemory(&m_callbackEnv, sizeof(m_callbackEnv));

		// Lock for m_workers list access from potentially multiple threads
		InitializeCriticalSectionAndSpinCount(&m_workersLock, 20);

		// Create our private thread pool
		m_pool = CreateThreadpool(NULL);
		if (!m_pool)
		{
			initResult = HRESULT_FROM_WIN32(GetLastError());
			goto exit;
		}

		// Setup pool for worker callbacks
		InitializeThreadpoolEnvironment(&m_callbackEnv);
		SetThreadpoolCallbackPool(&m_callbackEnv, m_pool);
		//SetThreadpoolCallbackRunsLong(&m_callbackEnv);
		SetThreadpoolCallbackPriority(&m_callbackEnv, TP_CALLBACK_PRIORITY_HIGH);		

		// Create a group for automated cleanup later
		m_cleanupGroup = CreateThreadpoolCleanupGroup();
		if (!m_cleanupGroup)
		{
			initResult = HRESULT_FROM_WIN32(GetLastError());
			goto exit;
		}
		SetThreadpoolCallbackCleanupGroup(&m_callbackEnv, m_cleanupGroup, NULL);
		initResult = ERROR_SUCCESS;

		exit:;
		if (initResult != ERROR_SUCCESS)
			Cleanup();
	}

	// Note: Queued callbacks are canceled, but started callbacks will block until they are completed
	~ConcurrentCallbackGroup() { Cleanup(); }

	// Get CPU logical (combined physical and HT/SMT) core counts
	static UINT32 GetLogicalCoreCount()
	{		
		SYSTEM_INFO nfo = { 0 };
		GetSystemInfo(&nfo);
		return nfo.dwNumberOfProcessors;
	}

private:
	struct WORKER
	{
		PTP_WORK work;
		BOOL enabled;
		ConcurrentCallbackGroup *self;

		WORKER_CALLBACK callback;
		PVOID lParm;		
	};
	std::list<WORKER> m_workers;
	CRITICAL_SECTION m_workersLock;
	inline void workers_lock() { EnterCriticalSection(&m_workersLock); }
	inline void workers_unlock() { LeaveCriticalSection(&m_workersLock); }

	long m_completed, m_workerErrors;
	UINT32 m_maxThreads; // On init optional max thread count override, after Start() the max threads in use
	BOOL m_started;
	
	PTP_POOL m_pool;
	PTP_CLEANUP_GROUP m_cleanupGroup;
	TP_CALLBACK_ENVIRON m_callbackEnv;

	// Local worker callback wrapper
	// Needs to be thread safe within our context
	static void CALLBACK CallbackWrapper(__in PTP_CALLBACK_INSTANCE pci, __inout PVOID lParm, __in PTP_WORK work)
	{
		WORKER &wrk = *((WORKER*) lParm);
		_ASSERT(wrk.work == work);

		// Call worker callback
		BOOL result = TRUE;
		__try
		{
			result = wrk.callback(wrk.lParm);
		}
		__except (ReportException("ConcurrentCallbackGroup::CallbackWrapper", GetExceptionInformation(), TRUE)){ result = TRUE; }

		if (result)
		{
			// return TRUE from the user callback indicates error status
			_InterlockedIncrement(&wrk.self->m_workerErrors);
		}

		_InterlockedIncrement(&wrk.self->m_completed);		
	}

	void Cleanup()
	{
		if (m_cleanupGroup)
		{
			// Cancels any pending callbacks and blocks for any running until they return, then releases
			// all of our worker objects for us.
			CloseThreadpoolCleanupGroupMembers(m_cleanupGroup, TRUE, NULL);
			CloseThreadpoolCleanupGroup(m_cleanupGroup);
			m_cleanupGroup = NULL;
		}

		if (m_pool)
		{
			CloseThreadpool(m_pool);
			m_pool = NULL;
		}
		
		m_workers.clear();
		DeleteCriticalSection(&m_workersLock);
	}
};
