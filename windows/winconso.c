/*
 * Console back end (Windows-specific).
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "winstuff.h"
#include <Tlhelp32.h>

#include "putty.h"

typedef struct console_backend_data {
    HANDLE hClientRead, hClientWrite, hServerWrite, hServerRead;
    HANDLE hProcess, hThread;
    struct handle *out, *in;
    DWORD dwProcessId;
    HWND hwnd;
	char title[1024];
    void *frontend;
    int bufsize;
} *Console;

static const char* base_title = "PuTTY Plus Console";
static int need_echo = 1;
CRITICAL_SECTION CriticalSection;
char cmd_buf[1024] = "\0";
int cmd_len = 0;

static DWORD WINAPI console_monitor_thread(void *param)
{
    Console console = (Console)param;

    if( WAIT_OBJECT_0==WaitForSingleObject(console->hProcess, INFINITE) )
    {
		__try
		{
			EnterCriticalSection(&CriticalSection);
			if (console->hServerWrite != INVALID_HANDLE_VALUE) {
				CloseHandle(console->hServerWrite);
        		console->hServerWrite = INVALID_HANDLE_VALUE;
			}
		}
		__finally
		{
			LeaveCriticalSection(&CriticalSection);
		}
    }

    return 0;
}

static BOOL process_has_childs(DWORD dwProcessId)
{
    return FALSE;
}

static BOOL close_process(DWORD dwProcessId)
{
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessId);
	if( hProcess )
	{
        DWORD dwExitCode = 0;
		TerminateProcess( hProcess,0 );
        // 等待进程退出
        WaitForSingleObject(hProcess, INFINITE);
        GetExitCodeProcess(hProcess, &dwExitCode);
		CloseHandle( hProcess );
	}
    return TRUE;
}

typedef BOOL (*process_handle)(DWORD);

static int find_child_process(DWORD dwProcessId, process_handle handle)
{
    PROCESSENTRY32 pe32;
	HANDLE hProcessSnap;
	BOOL bMore = FALSE;
    int count = 0;

    pe32.dwSize = sizeof(pe32);

    //   给系统内的所有进程拍一个快照
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return count;
    }

    //   遍历进程快照，轮流显示每个进程的信息
    bMore = Process32First(hProcessSnap, &pe32);
    while(bMore)
    {
        if(pe32.th32ParentProcessID == dwProcessId)
        {
            // 找到一个子进程，结束它
            if(handle)
            {
                ++count;
                if( (handle)(pe32.th32ProcessID) == FALSE )
                    break;
            }
        }
        bMore = Process32Next(hProcessSnap, &pe32);
    }

    //   不要忘记清除掉snapshot对象
    CloseHandle(hProcessSnap);
    return count;
}

static void console_terminate(Console console)
{
//	int ret;
//    WriteFile(console->hWrite, "exit\n", strlen("exit\n"), &ret, NULL);
//	Sleep(200);
    find_child_process(console->dwProcessId, close_process);
    close_process(console->dwProcessId);
    console->dwProcessId = (DWORD)(-1);
    
    if (console->hServerRead != INVALID_HANDLE_VALUE) {
        if( !CloseHandle(console->hServerRead) )
        {
        }
    	console->hServerRead = INVALID_HANDLE_VALUE;
    }
	__try
	{
        EnterCriticalSection(&CriticalSection);
        if (console->hServerWrite != INVALID_HANDLE_VALUE) {
            if( !CloseHandle(console->hServerWrite) )
            {
            }
        	console->hServerWrite = INVALID_HANDLE_VALUE;
        }
	}
	__finally
	{
		LeaveCriticalSection(&CriticalSection);
	}
    Sleep(100);
    
    if (console->hClientWrite != INVALID_HANDLE_VALUE) {
        if( !CloseHandle(console->hClientWrite) )
        {
        }
    	console->hClientWrite = INVALID_HANDLE_VALUE;
    }
    if (console->hClientRead != INVALID_HANDLE_VALUE) {
    	if( !CloseHandle(console->hClientRead) )
    	{
    	}
    	console->hClientRead = INVALID_HANDLE_VALUE;
    }

    if (console->out) {
    	handle_free(console->out);
    	console->out = NULL;
    }
    if (console->in) {
    	handle_free(console->in);
    	console->in = NULL;
    }
}

static int console_gotdata(struct handle *h, void *data, int len)
{
    Console console = (Console)handle_get_privdata(h);
    if (len <= 0) {
        const char *error_msg;
    	/*
    	 * Currently, len==0 should never happen because we're
    	 * ignoring EOFs. However, it seems not totally impossible
    	 * that this same back end might be usable to talk to named
    	 * pipes or some other non-console device, in which case EOF
    	 * may become meaningful here.
    	 */
        if (len == 0)
            error_msg = "End of file reading from console device";
        else
            error_msg = "Error reading from console device";

        console_terminate(console);
        notify_remote_exit(console->frontend);
        logevent(console->frontend, error_msg);
        connection_fatal(console->frontend, "%s", error_msg);
        return 0;
    } else {
        BOOL no_child = (find_child_process(console->dwProcessId, process_has_childs)==0);
        if( no_child != need_echo )
        {
            cmd_buf[0] = 0;
            cmd_len = 0;
            need_echo = no_child;
        }
        return from_backend(console->frontend, 0, data, len);
    }
}

static void console_sentdata(struct handle *h, int new_backlog)
{
    Console console = (Console)handle_get_privdata(h);
    if (new_backlog < 0) {
        const char *error_msg = "Error writing to console device";
        console_terminate(console);
        notify_remote_exit(console->frontend);
        logevent(console->frontend, error_msg);
        connection_fatal(console->frontend, "%s", error_msg);
    } else {
        console->bufsize = new_backlog;
    }
}

/*
 * Called to set up the console connection.
 * 
 * Returns an error message, or NULL on success.
 *
 * Also places the canonical host name into `realhost'. It must be
 * freed by the caller.
 */
static const char *console_init(void *frontend_handle, void **backend_handle,
			       Conf *conf, char *host, int port,
			       char **realhost, int nodelay, int keepalive)
{
    Console console;
    SECURITY_ATTRIBUTES sa;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
    HANDLE  hClientRead,hServerWrite;
    HANDLE  hClientWrite,hServerRead;
	char shellCmd[_MAX_PATH];
    DWORD monitor_threadid;

    InitializeCriticalSection(&CriticalSection);

    term_do_paste(term);
    
    console = snew(struct console_backend_data);
    console->out = console->in = NULL;
    console->bufsize = 0;
    *backend_handle = console;
    console->frontend = frontend_handle;
    console->dwProcessId = (DWORD)(-1);
	console->hwnd = NULL;
    
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if( !CreatePipe(&hClientRead, &hServerWrite, &sa, 4096) ) 
    {
        return "Create pipe1 failed!";
    }
    if( !CreatePipe(&hServerRead, &hClientWrite, &sa, 4096) ) 
    {
        return "Create pipe2 failed!";
    }

	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
	si.wShowWindow = SW_SHOWNORMAL;//SW_HIDE;
	si.hStdOutput = hServerWrite;
	si.hStdError = hServerWrite;
	si.hStdInput = hServerRead;
    si.lpTitle = base_title;

	if( !GetEnvironmentVariable(("ComSpec"), shellCmd, _MAX_PATH) )
		  return "Can not found cmd.exe";
    
	strcat( shellCmd, (" /A") );// /C d:\\rockadb\\tools\\adb.exe shell

	if( !CreateProcess(NULL, shellCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) )
	{
        return "Create process failed!";
	}

#if 0
/*
    if( !CloseHandle(pi.hProcess) )
    {
        return "CloseHandle(pi.hProcess) failed!";
    }
	*/
    if( !CloseHandle(pi.hThread) )
    {
        return "CloseHandle(pi.hThread) failed!";
    }
    /*
    if( !CloseHandle(hServerRead) )
    {
        return "CloseHandle(hServerRead) failed!";
    }
    */
#endif

    console->dwProcessId = pi.dwProcessId;
    console->hThread = pi.hThread;
    console->hProcess = pi.hProcess;
    
    console->hClientRead = hClientRead;
    console->hClientWrite = hClientWrite;
    console->hServerWrite = hServerWrite;
    console->hServerRead = hServerRead;
    
    #if 0
    console->out = handle_output_new(console->hWrite, console_sentdata, console,
				    HANDLE_FLAG_OVERLAPPED);
    console->in = handle_input_new(console->hRead, console_gotdata, console,
				  HANDLE_FLAG_OVERLAPPED |
				  HANDLE_FLAG_IGNOREEOF |
				  HANDLE_FLAG_UNITBUFFER);
    #else
    console->out = handle_output_new(console->hClientWrite, console_sentdata, console, 0);
    console->in = handle_input_new(console->hClientRead, console_gotdata, console, HANDLE_FLAG_IGNOREEOF);
    #endif
    
    // create monitor thread for child process exit
    CreateThread(NULL, 0, console_monitor_thread,
		        (void*)console, 0, &monitor_threadid);

//    need_echo = 1;
    
    *realhost = dupstr("Console");
    update_specials_menu(console->frontend);

    return NULL;
}

static void console_free(void *handle)
{
    Console console = (Console) handle;
    console_terminate(console);
    expire_timer_context(console);
    sfree(console);
    DeleteCriticalSection(&CriticalSection);
}

static void console_reconfig(void *handle, Conf *conf)
{
}

static int key_process(char *buf, char *key, int len)
{
    if( !strncmp("\0x1B\0x5B\0x41", key, len) )
    {// UP
    }
    else if( !strncmp("\0x1B\0x5B\0x42", key, len) )
    {// DOWN
    }
    else if( !strncmp("\0x1B\0x5B\0x43", key, len) )
    {// RIGHT
    }
    else if( !strncmp("\0x1B\0x5B\0x44", key, len) )
    {// LEFT
    }
    else if( !strncmp("\0x1B\0x5B\0x31\0x7E", key, len) )
    {// HOME
    }
    else if( !strncmp("\0x1B\0x5B\0x34\0x7E", key, len) )
    {// END
    }
    else if( !strncmp("\0x1B\0x5B\0x33\0x7E", key, len) )
    {// DELETE
    }
    return 1;
}

/*
 * Called to send data down the console connection.
 */
static int console_send(void *handle, char *buf, int len)
{
    Console console = (Console) handle;
    int ret = 0;

    if (console->out == NULL)
    	return 0;

    if (need_echo)
    {
        key_process(cmd_buf, buf, len);
        
        EnterCriticalSection(&CriticalSection);
        if(console->hServerWrite)
            WriteFile(console->hServerWrite, buf, len, &ret, NULL);
        LeaveCriticalSection(&CriticalSection);
        
        strncpy(cmd_buf+cmd_len, buf, len);
        cmd_len += len;
        if(cmd_buf[cmd_len-1] == '\r')
        {
            cmd_buf[cmd_len] = '\n';
            cmd_buf[cmd_len+1] = 0;
            ++cmd_len;
            console->bufsize = handle_write(console->out, cmd_buf, cmd_len);
            cmd_buf[0] = 0;
            cmd_len = 0;
        }
        else
            console->bufsize = 0;
    }
    else
    {
        if(buf[len-1] == '\r')
        {
            buf[len] = '\n';
            buf[++len] = 0;
        }

        console->bufsize = handle_write(console->out, buf, len);
    }

    return console->bufsize;
}

/*
 * Called to query the current sendability status.
 */
static int console_sendbuffer(void *handle)
{
    Console console = (Console) handle;
    return console->bufsize;
}

/*
 * Called to set the size of the window
 */
static void console_size(void *handle, int width, int height)
{
    /* Do nothing! */
    return;
}

/*
 * Send console special codes.
 */
static void console_special(void *handle, Telnet_Special code)
{
    return;
}

/*
 * Return a list of the special codes that make sense in this
 * protocol.
 */
static const struct telnet_special *console_get_specials(void *handle)
{
    static const struct telnet_special specials[] = {
	{NULL, TS_EXITMENU}
    };
    return specials;
}

static int console_connected(void *handle)
{
    return 1;			       /* always connected */
}

static int console_sendok(void *handle)
{
    return 1;
}

static void console_unthrottle(void *handle, int backlog)
{
    Console console = (Console) handle;
    if (console->in)
    	handle_unthrottle(console->in, backlog);
}

static int console_ldisc(void *handle, int option)
{
    /*
     * Local editing and local console are off by default.
     */
    return 0;
}

static void console_provide_ldisc(void *handle, void *ldisc)
{
    /* This is a stub. */
}

static void console_provide_logctx(void *handle, void *logctx)
{
    /* This is a stub. */
}

static int console_exitcode(void *handle)
{
    Console console = (Console) handle;
    if (console->hClientWrite != INVALID_HANDLE_VALUE
        || console->hClientRead != INVALID_HANDLE_VALUE)
        return -1;                     /* still connected */
    else
        /* Exit codes are a meaningless concept with console ports */
        return INT_MAX;
}

/*
 * cfg_info for Console does nothing at all.
 */
static int console_cfg_info(void *handle)
{
    return 0;
}

Backend console_backend = {
    console_init,
    console_free,
    console_reconfig,
    console_send,
    console_sendbuffer,
    console_size,
    console_special,
    console_get_specials,
    console_connected,
    console_exitcode,
    console_sendok,
    console_ldisc,
    console_provide_ldisc,
    console_provide_logctx,
    console_unthrottle,
    console_cfg_info,
    "console",
    PROT_CONSOLE,
    0
};
