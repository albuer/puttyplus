/*
 * Console back end (Windows-specific).
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "putty.h"

//#define SUPPORT_CMD

typedef struct console_backend_data {
    HANDLE hRead, hWrite, hToRead;
    struct handle *out, *in;
    DWORD dwProcessId;
    HWND hwnd;
	char title[1024];
    void *frontend;
    int bufsize;
} *Console;

static const char* base_title = "PuTTY Plus Console";
#ifdef SUPPORT_CMD
static int need_echo = 1;
#endif

static void console_terminate(Console console)
{
//	int ret;
//    WriteFile(console->hWrite, "exit\n", strlen("exit\n"), &ret, NULL);
//	Sleep(200);
	if( console->dwProcessId!=(DWORD)(-1) )
	{
		HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, console->dwProcessId );
		if( hProcess )
		{
            DWORD dwExitCode = 0;
			TerminateProcess( hProcess,0 );
            WaitForSingleObject(hProcess, INFINITE);
            GetExitCodeProcess(hProcess, &dwExitCode);
			CloseHandle( hProcess );
		}
        console->dwProcessId = (DWORD)(-1);
	}
    
    if (console->hToRead != INVALID_HANDLE_VALUE) {
        if( !CloseHandle(console->hToRead) )
        {
            MessageBox(NULL, "CloseHandle(console->hToRead)", "", MB_OK);
        }
    	console->hToRead = INVALID_HANDLE_VALUE;
        Sleep(200);
    }
    
    if (console->hWrite != INVALID_HANDLE_VALUE) {
        if( !CloseHandle(console->hWrite) )
        {
            MessageBox(NULL, "CloseHandle(console->hWrite)", "", MB_OK);
        }
    	console->hWrite = INVALID_HANDLE_VALUE;
    }
    if (console->hRead != INVALID_HANDLE_VALUE) {
    	if( !CloseHandle(console->hRead) )
    	{
            MessageBox(NULL, "CloseHandle(console->hRead)", "", MB_OK);
    	}
    	console->hRead = INVALID_HANDLE_VALUE;
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
    
	strcat( shellCmd, (" /A /C d:\\rockadb\\tools\\adb.exe shell") );//

	if( !CreateProcess(NULL, shellCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) )
	{
        return "Create process failed!";
	}
    if( !CloseHandle(pi.hProcess) )
    {
        return "CloseHandle(pi.hProcess) failed!";
    }
    if( !CloseHandle(pi.hThread) )
    {
        return "CloseHandle(pi.hThread) failed!";
    }
    if( !CloseHandle(hServerRead) )
    {
        return "CloseHandle(hServerRead) failed!";
    }

    console->dwProcessId = pi.dwProcessId;
    console->hRead = hClientRead;
    console->hWrite = hClientWrite;
    console->hToRead = hServerWrite;
    #if 0
    console->out = handle_output_new(console->hWrite, console_sentdata, console,
				    HANDLE_FLAG_OVERLAPPED);
    console->in = handle_input_new(console->hRead, console_gotdata, console,
				  HANDLE_FLAG_OVERLAPPED |
				  HANDLE_FLAG_IGNOREEOF |
				  HANDLE_FLAG_UNITBUFFER);
    #else
    console->out = handle_output_new(console->hWrite, console_sentdata, console, 0);
    console->in = handle_input_new(console->hRead, console_gotdata, console, HANDLE_FLAG_IGNOREEOF);
    #endif
#ifdef SUPPORT_CMD
    need_echo = 1;
#endif
    
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
}

static void console_reconfig(void *handle, Conf *conf)
{
}

char cmd[1024] = "\0";
int cmd_len = 0;
/*
 * Called to send data down the console connection.
 */
static int console_send(void *handle, char *buf, int len)
{
    Console console = (Console) handle;
    int ret = 0;
	char title[1024];

    if (console->out == NULL)
    	return 0;

	if( console->hwnd==NULL )
	{
		HWND hwnd = NULL;
    
		while( hwnd=FindWindowEx(hwnd, NULL, "ConsoleWindowClass",NULL) )
		{
			GetWindowText(hwnd, title, 1024);
			if( !strncmp(title, base_title, strlen(base_title)) )
			{
                DWORD pid = 0;
                GetWindowThreadProcessId(hwnd, &pid);
                if(pid == console->dwProcessId)
                {
    				console->hwnd = hwnd;
    				strcpy(console->title, title);
                    break;
                }
			}
		}
	}
#ifdef SUPPORT_CMD
	if( console->hwnd==NULL )
	{
		HWND hwnd = NULL;
    
		while( hwnd=FindWindowEx(hwnd, NULL, "ConsoleWindowClass",NULL) )
		{
			GetWindowText(hwnd, title, 1024);
			if( !strncmp(title, base_title, strlen(base_title)) )
			{
                DWORD pid = 0;
                GetWindowThreadProcessId(hwnd, &pid);
                if(pid == console->dwProcessId)
                {
    				console->hwnd = hwnd;
    				strcpy(console->title, title);
                    break;
                }
			}
		}
	}
	else
	{
		GetWindowText(console->hwnd, title, 1024);
		if( strcmp(title, console->title) )
		{
			strcpy(console->title, title);
		}
        if( strcmp(console->title, base_title) )
        {
            need_echo = 0;
        } else {
            need_echo = 1;
        }
	}

    // lost console
    if( console->hwnd==NULL )
    {
        logevent(console->frontend, "Error reading from console device");
        return 0;
    }
        
    if (need_echo)
    {
        if(console->hToRead)
            WriteFile(console->hToRead, buf, len, &ret, NULL);
        
        strncpy(cmd+cmd_len, buf, len);
        cmd_len += len;
        if(cmd[cmd_len-1] == '\r')
        {
            cmd[cmd_len] = '\n';
            cmd[cmd_len+1] = 0;
            ++cmd_len;
            console->bufsize = handle_write(console->out, cmd, cmd_len);
            cmd[0] = 0;
            cmd_len = 0;
            return console->bufsize;
        }
        return 0;
    }
    else
    {
        cmd[0] = 0;
        cmd_len = 0;
    }
#else
    strncpy(cmd+cmd_len, buf, len);
    cmd_len += len;
    if(cmd[cmd_len-1] == '\r')
    {
        cmd[cmd_len] = '\n';
        cmd[cmd_len+1] = 0;
        ++cmd_len;
        if(!strncmp(cmd, "exit", 4))
        {
        }
        cmd[0] = 0;
        cmd_len = 0;
    }
#endif

    if(buf[len-1] == '\r')
    {
        buf[len] = '\n';
        buf[len+1] = 0;
        ++len;
    }

    console->bufsize = handle_write(console->out, buf, len);

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
    if (console->hWrite != INVALID_HANDLE_VALUE
        || console->hRead != INVALID_HANDLE_VALUE)
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
