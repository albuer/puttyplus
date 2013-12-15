/*
 * Console back end (Windows-specific).
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "winstuff.h"
#include <Tlhelp32.h>

#include "putty.h"
#include "cmdhistory.h"

int left_limit_x, left_limit_y;
int right_limit_x, right_limit_y;

typedef struct console_backend_data {
    HANDLE hClientRead, hClientWrite, hServerWrite, hServerRead;
    struct handle *out, *in;
    DWORD dwProcessId;
    void *frontend;
    int bufsize;
} *Console;

typedef BOOL (*process_handle)(DWORD);

typedef struct{
    LPSECURITY_ATTRIBUTES lpPipeAttributes;
    PHANDLE hPipe;
    LPTSTR lpszPipename;
} CREATE_PIPE;

static const char* base_title = "PuTTY Plus Console";
static int need_echo = 1;

#define BUFSIZE 2048
#define BASE_PIPENAME "\\\\.\\pipe\\puttyplus"

static DWORD WINAPI get_write_pipe_thread(void *param)
{
    CREATE_PIPE* pipeParam = (CREATE_PIPE*)param;
	HANDLE hPipe;

	if( !WaitNamedPipe(pipeParam->lpszPipename, NMPWAIT_WAIT_FOREVER) )
	{
		int err = GetLastError();
		return -1;
	}

	hPipe = CreateFile(pipeParam->lpszPipename,
						GENERIC_WRITE,
						0,
						pipeParam->lpPipeAttributes,
						OPEN_EXISTING,
						FILE_FLAG_OVERLAPPED,
						NULL);

	if( INVALID_HANDLE_VALUE == hPipe )
	{
		int err = GetLastError();
		return -1;
	}

	*pipeParam->hPipe = hPipe;

	return 0;
}

static BOOL CreateNamedPipePair(PHANDLE hReadPipe, 
                         PHANDLE hWritePipe, 
                         LPSECURITY_ATTRIBUTES lpPipeAttributes, 
                         DWORD nSize)
{
	HANDLE hEvent;
	HANDLE hPipeR = INVALID_HANDLE_VALUE;
    HANDLE hPipeW = INVALID_HANDLE_VALUE;
	OVERLAPPED lp;
    DWORD threadid;
    HANDLE hClientThread;
    CREATE_PIPE *pcreate_pipe_param;
    char pipename[512];
    static DWORD dwAccumulator = 0;
    sprintf( pipename, "%s_%08X_%08X", BASE_PIPENAME, GetTickCount(), dwAccumulator++ );

	hPipeR = CreateNamedPipe( 
				pipename,
				PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
				0,
				1,
				nSize,
				nSize,
				0,
				lpPipeAttributes);
	if( INVALID_HANDLE_VALUE == hPipeR )
	{
		int err = GetLastError();
		return FALSE;
	}

	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if(hEvent == NULL)
	{
		int err = GetLastError();
		CloseHandle(hPipeR);
		return FALSE;
	}

	ZeroMemory(&lp, sizeof(OVERLAPPED));
	lp.hEvent = hEvent;

	if( !ConnectNamedPipe(hPipeR, &lp) )
	{
		if( ERROR_IO_PENDING != GetLastError() )
		{
			int err = GetLastError();
			CloseHandle(hEvent);
			CloseHandle(hPipeR);
			return FALSE;
		}
	}

	// 创建线程，用于获取 pipe_client
	pcreate_pipe_param = (CREATE_PIPE*)malloc(sizeof(CREATE_PIPE));
    pcreate_pipe_param->lpPipeAttributes = lpPipeAttributes;
    pcreate_pipe_param->hPipe = &hPipeW;
    pcreate_pipe_param->lpszPipename = pipename;
    
	hClientThread = CreateThread(NULL, 0, get_write_pipe_thread, 
                                    pcreate_pipe_param, 0, &threadid);
    WaitForSingleObject(hClientThread, INFINITE);
    free(pcreate_pipe_param);
    
    if(hPipeW == INVALID_HANDLE_VALUE)
    {
        int err = GetLastError();
		CloseHandle(hEvent);
		CloseHandle(hPipeR);
		CloseHandle(hClientThread);
        return FALSE;
    }
    CloseHandle(hClientThread);

    // 等待直到Client连接到Server
	if(WAIT_FAILED == WaitForSingleObject(hEvent, INFINITE))
	{
		int err = GetLastError();
		CloseHandle(hEvent);
		CloseHandle(hPipeR);
        CloseHandle(hPipeW);
		return FALSE;
	}

	CloseHandle(hEvent);
    
    *hReadPipe = hPipeR;
    *hWritePipe = hPipeW;
    return TRUE;
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

static int check_newline(char* data, int len)
{
    int len_o=len;
    while(len>0) {
         if((*data==0x0a) && (len_o==len || (*(data-1)!=0x0d)))
            return 1;
         ++data;
         --len;
    }
    return 0;
}

static int revise_newline(char* buff, char* data, int len)
{
    int buff_len = 0;
    int len_o=len;
    while(len>0)
    {
        if((*data==0x0a) && (len_o==len || (*(data-1)!=0x0d)))
        {
            *buff++ = 0x0d;
			++buff_len;
        }
        *buff++ = *data++;
        ++buff_len;
        --len;
    }
    return buff_len;
}

static void console_terminate(Console console)
{
    // 关闭子进程及该子进程创建的所有进程
    find_child_process(console->dwProcessId, close_process);
    close_process(console->dwProcessId);
    console->dwProcessId = (DWORD)(-1);

    if (console->hClientWrite != INVALID_HANDLE_VALUE) {
        CloseHandle(console->hClientWrite);
    	console->hClientWrite = INVALID_HANDLE_VALUE;
    }
    if (console->hClientRead != INVALID_HANDLE_VALUE) {
    	CloseHandle(console->hClientRead);
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
    // clear cmd history list
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
        // need echo if no child process
        BOOL no_child = (find_child_process(console->dwProcessId, process_has_childs)==0);
        if( no_child != need_echo )
        {
			// clean cmd buffer
			cmdh_init();
            need_echo = no_child;
        }

        if (check_newline(data, len))
        {
            char buff[BUFSIZE*2];
            int buff_len = revise_newline(buff, data, len);
            from_backend(console->frontend, 0, buff, buff_len);
        }
        else
            from_backend(console->frontend, 0, data, len);

        if(need_echo)
            from_backend_pos(console->frontend, &left_limit_x, &left_limit_y);
        return 0;
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
	char shellCmd[_MAX_PATH];
    char *prgm;

    int* test = malloc(4);

    // Initial Console struct
    console = snew(struct console_backend_data);
    console->out = console->in = NULL;
    console->bufsize = 0;
    *backend_handle = console;
    console->frontend = frontend_handle;
    console->dwProcessId = (DWORD)(-1);
    
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if( !CreateNamedPipePair(&console->hClientRead, &console->hServerWrite, &sa, BUFSIZE) ) 
    {
        return "Create pipe1 failed!";
    }
    if( !CreateNamedPipePair(&console->hServerRead, &console->hClientWrite, &sa, BUFSIZE) ) 
    {
        return "Create pipe2 failed!";
    }

	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = console->hServerWrite;
	si.hStdError = console->hServerWrite;
	si.hStdInput = console->hServerRead;

	if( !GetEnvironmentVariable(("ComSpec"), shellCmd, _MAX_PATH) )
		  return "Can not found cmd.exe";
    
    prgm = conf_get_str(conf, CONF_consoleprgm);
    
	strcat( shellCmd, (" /A") );
    need_echo = 1;
	if( prgm[0] )
	{
		strcat(shellCmd, " /C ");
        strcat(shellCmd, prgm);
        need_echo = 0;
	}

    {
    	char *msg = dupprintf("running program: %s", prgm);
    	logevent(console->frontend, msg);
    }

	if( !CreateProcess(NULL, shellCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) )
	{
        return "Create process failed!";
	}
    Sleep(100);

    CloseHandle(pi.hThread);
    CloseHandle(console->hServerWrite);
    CloseHandle(console->hServerRead);

    console->dwProcessId = pi.dwProcessId;
    
    console->out = handle_output_new(console->hClientWrite, console_sentdata, console,
				    HANDLE_FLAG_OVERLAPPED, pi.hProcess);
    console->in = handle_input_new(console->hClientRead, console_gotdata, console,
				  HANDLE_FLAG_OVERLAPPED |
				  HANDLE_FLAG_IGNOREEOF, pi.hProcess);

    cmdh_init();

    *realhost = dupstr(prgm);

    update_specials_menu(console->frontend);

    return NULL;
}

static void console_free(void *handle)
{
    Console console = (Console) handle;
    cmdh_free();
    console_terminate(console);
    expire_timer_context(console);
    sfree(console);
}

static void console_reconfig(void *handle, Conf *conf)
{
    Console console = (Console) handle;
    logevent(console->frontend, "console_reconfig");
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
        const char *show = NULL;
        const char *send = NULL;
        buf[len] = '\0';
        console->bufsize = 0;
        cmd_add_char(buf, len, &show, &send);
        if(show)
        {
            from_backend(console->frontend, 0, show, strlen(show));
            from_backend_pos(console->frontend, &right_limit_x, &right_limit_y);
        }
        if(send)
            console->bufsize = handle_write(console->out, send, strlen(send));
    }
    else
    {
        if(buf[len-1] == '\r')
        {
            buf[len-1] = '\n';
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
    Console console = (Console) handle;
    logevent(console->frontend, "console_special");
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
    Console console = (Console) handle;
    logevent(console->frontend, "console_connected");
    return 1;			       /* always connected */
}

static int console_sendok(void *handle)
{
    Console console = (Console) handle;
    logevent(console->frontend, "console_sendok");
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
    Console console = (Console) handle;
    logevent(console->frontend, "console_ldisc");
    return 0;
}

static void console_provide_ldisc(void *handle, void *ldisc)
{
    /* This is a stub. */
    Console console = (Console) handle;
    logevent(console->frontend, "console_provide_ldisc");
}

static void console_provide_logctx2(void *handle, void *logctx)
{
    /* This is a stub. */
    Console console = (Console) handle;
    logevent(console->frontend, "console_provide_logctx2");
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
    Console console = (Console) handle;
    logevent(console->frontend, "console_cfg_info");
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
    console_provide_logctx2,
    console_unthrottle,
    console_cfg_info,
    "console",
    PROT_CONSOLE,
    0
};
