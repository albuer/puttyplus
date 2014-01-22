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
#include "terminal.h"

#define poslt(p1,p2) ( (p1).y < (p2).y || ( (p1).y == (p2).y && (p1).x < (p2).x ) )
#define posle(p1,p2) ( (p1).y < (p2).y || ( (p1).y == (p2).y && (p1).x <= (p2).x ) )
#define poseq(p1,p2) ( (p1).y == (p2).y && (p1).x == (p2).x )

static void console_presend(void *handle, char *buf, int len);

static pos cursor_pos, left_limit_pos, right_limit_pos;

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
static int win_console = 1;

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

BOOL CreateNamedPipePair(PHANDLE hReadPipe, 
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

static int is_only_newline(char* data, int len)
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

// 确保一行字符串是以回车或者回车换行符来结束。
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
}

// 当对端有数据输出时，调用该函数来处理
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
        if( no_child != win_console )
        {
            win_console = no_child;
        }

        if (is_only_newline(data, len))
        {
            char buff[BUFSIZE*2];
            int buff_len = revise_newline(buff, data, len);
            from_backend(console->frontend, 0, buff, buff_len);
        }
        else {
            from_backend(console->frontend, 0, data, len);
        }

        if(win_console){
            from_backend_pos(console->frontend, &left_limit_pos.x, &left_limit_pos.y);
            cursor_pos.x = left_limit_pos.x;
            cursor_pos.y = left_limit_pos.y;
        }
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
    win_console = 1;
	if( prgm[0] )
	{
		strcat(shellCmd, " /C ");
        strcat(shellCmd, prgm);
        win_console = 0;
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
// 在主界面上输入的字符，将被送到此处
static int console_send(void *handle, char *buf, int len)
{
    Console console = (Console) handle;
    int ret = 0;

    if (console->out == NULL)
    	return 0;

// 对于类Linux的console，在把字符送给它们时，它们会把该字符回显，
// 从而在console_gotdata我们可以得到该字符并自动送到前端显示。
// 对于windows console，送给它们的字符并不会回显，也就不会回调console_gotdata函数，
// 因此我们需要手动回显(把字符送给前端显示)
    if (win_console)
    {
        console->bufsize = winconso_send(handle, buf, len);
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
    return 1;			       /* always connected */
}

static int console_sendok(void *handle)
{
    Console console = (Console) handle;
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
    return 0;
}

static void console_provide_ldisc(void *handle, void *ldisc)
{
    /* This is a stub. */
    Console console = (Console) handle;
}

static void console_provide_logctx2(void *handle, void *logctx)
{
    /* This is a stub. */
    Console console = (Console) handle;
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

#define MAX_CMD_LENGTH  8192
static char cmd_buff[MAX_CMD_LENGTH] = "";

enum{
    CTRL_KEY_NOT = 0,
    CTRL_KEY_UP,
    CTRL_KEY_DOWN,
    CTRL_KEY_RIGHT,
    CTRL_KEY_LEFT,
    CTRL_KEY_HOME,
    CTRL_KEY_END,
    CTRL_KEY_DELETE,
    CTRL_KEY_BACKSPACE,
    CTRL_KEY_BREAK,
    CTRL_KEY_TAB,
    CTRL_KEY_OTHER,
};

static int key_translate(const char *key, int len)
{
    int result = CTRL_KEY_NOT;
    
    if( !strncmp("\x1B[A", key, len) )
    {// UP
        result = CTRL_KEY_UP;
    }
    else if( !strncmp("\x1B[B", key, len) )
    {// DOWN
        result = CTRL_KEY_DOWN;
    }
    else if( !strncmp("\x1B[C", key, len) )
    {// RIGHT
        result = CTRL_KEY_RIGHT;
    }
    else if( !strncmp("\x1B[D", key, len) )
    {// LEFT
        result = CTRL_KEY_LEFT;
    }
    else if( !strncmp("\x1B[1~", key, len) )
    {// HOME
        result = CTRL_KEY_HOME;
    }
    else if( !strncmp("\x1B[4~", key, len) )
    {// END
        result = CTRL_KEY_END;
    }
    else if( !strncmp("\x1B[3~", key, len) )
    {// DELETE
        result = CTRL_KEY_DELETE;
    }
    else if( !strncmp("\x7F", key, len) )
    {// BACKSPACE
        result = CTRL_KEY_BACKSPACE;
    }
    else if( !strncmp("\x03", key, len) )
    {// Break
        result = CTRL_KEY_BREAK;
    }
    else if( !strncmp("\x09", key, len) )
    {// Tab
        result = CTRL_KEY_TAB;
    }
    else if( key[0]=='\x1B' )
    {// other control key
        result = CTRL_KEY_OTHER;
    }
    
    return result;
}

static void goto_home(char* to_frontend)
{
    int i=0;
    for(i=0; i<(cursor_pos.y-left_limit_pos.y); i++)
    {
        strcat(to_frontend, "\x1B[A"); // up
    }
    strcat(to_frontend, "\x0D"); // return
    for (i=0; i<left_limit_pos.x; i++)
    {
        strcat(to_frontend, "\x1B[C"); // right
    }
}

static void clean_line(char* to_frontend)
{
    int i=0;
    char deletes_str[10];

    goto_home(to_frontend);

    sprintf(deletes_str, "\x1B[%dP", term_get_cols() - left_limit_pos.x);
    strcat(to_frontend, deletes_str);
    for(i=(right_limit_pos.y-left_limit_pos.y); i>0; i--)
    {
        strcat(to_frontend,"\r\n");
        if(i==1)
        {
            sprintf(deletes_str, "\x1B[%dP", right_limit_pos.x);
        }
        else
            sprintf(deletes_str, "\x1B[%dP", term_get_cols());
        strcat(to_frontend, deletes_str);
        strcat(to_frontend, "\x1B[K");
    }

    for(i=0; i<(right_limit_pos.y-left_limit_pos.y); i++)
    {
        strcat(to_frontend, "\x1B[A"); // up
    }
    strcat(to_frontend, "\x0D"); // return
    for (i=0; i<left_limit_pos.x; i++)
    {
        strcat(to_frontend, "\x1B[C"); // right
    }
}

// 返回值:  送入后端的字符个数
static int winconso_send(void *handle, char *buf, int len)
{
    Console console = (Console) handle;
    int is_cmd_comp = 0;
    char to_frontend[MAX_CMD_LENGTH] = "";

    if (cmd_buff[0]=='\0') {
    }

    term_get_pos(&left_limit_pos, &right_limit_pos, strlen(cmd_buff));

    switch (key_translate(buf, len))
    {
    case CTRL_KEY_UP:
        {
            char* pcmd = cmdh_get(1);
            if(pcmd) {
                clean_line(to_frontend);
                strcat(to_frontend, pcmd);
                sprintf(cmd_buff, "%s", pcmd);
            }
        }
        break;
    case CTRL_KEY_DOWN:
        {
            char* pcmd = cmdh_get(0);
            if(pcmd) {
                clean_line(to_frontend);
                strcat(to_frontend, pcmd);
                sprintf(cmd_buff, "%s", pcmd);
            }
        }
        break;
    case CTRL_KEY_LEFT:
        if (posle(cursor_pos, left_limit_pos))
            sprintf(to_frontend, "\x07"); // bell
        else if(cursor_pos.x==0) // 到上一行
        {
            int i=0;
            sprintf(to_frontend, "\x1B[A"); // up
            for(i=0;i<(term_get_cols()-1);i++)
            {
                strcat(to_frontend, "\x1B[C"); // right
            }
        }
        else
            sprintf(to_frontend, "\x08");
        break;
    case CTRL_KEY_RIGHT:
        if (posle(right_limit_pos, cursor_pos))
            sprintf(to_frontend, "\x07"); // bell
        else if (cursor_pos.x == (term_get_cols()-1))
        {
            int i=0;
            sprintf(to_frontend, "\x1B[B"); // down
            for(i=0;i<(term_get_cols()-1);i++)
            {
                strcat(to_frontend, "\x08"); // left
            }
        }
        else
            sprintf(to_frontend, "\x1B[C");
        break;
    case CTRL_KEY_HOME:
        if (poseq(cursor_pos, left_limit_pos))
            sprintf(to_frontend, "\x07"); // bell
        else
            goto_home(to_frontend);
        break;
    case CTRL_KEY_END:
        if (poseq(cursor_pos, right_limit_pos))
            sprintf(to_frontend, "\x07"); // bell
        else
        {
            int i=0;
            for(i=0; i<(right_limit_pos.y-cursor_pos.y); i++)
            {
                strcat(to_frontend, "\x1B[B"); // down
            }
            strcat(to_frontend, "\x0D"); // return
            for (i=0; i<right_limit_pos.x; i++)
            {
                strcat(to_frontend, "\x1B[C"); // right
            }
        }
        break;
    case CTRL_KEY_BACKSPACE:
        if (posle(cursor_pos, left_limit_pos)){
            sprintf(to_frontend, "\x07"); // bell
            break;
        } else {
            int i=0;
            char* p = cmd_buff+term_posdiff(&cursor_pos, &left_limit_pos)-1;
            char* p2 = p;
            sprintf(to_frontend, "\x08"); // left
            while(*p){
                *p = *(p+1);
                ++p;
            }
            p = p2;
            strcat(to_frontend, p);

            if (right_limit_pos.x==1) //删除一个字符后将会空出一行
            {
                if(cursor_pos.y!=right_limit_pos.y)
                    strcat(to_frontend, "\r\n"); // 
                strcat(to_frontend, "\x1B[K"); // break
            } 
            else if (poseq(cursor_pos, right_limit_pos))
                strcat(to_frontend, "\x1B[K"); // break
            else
                strcat(to_frontend, "\x1B[1P"); // delete
            for(i=0; i<strlen(p); i++)
                strcat(to_frontend, "\x08"); // left
        }
        break;
    case CTRL_KEY_DELETE:
        if (poseq(cursor_pos, right_limit_pos))
            sprintf(to_frontend, "\x07"); // bell
        else
        {
            int i=0;
            char* p = cmd_buff+term_posdiff(&cursor_pos, &left_limit_pos);
            char* p2 = p;
            while(*p){
                *p = *(p+1);
                ++p;
            }
            p = p2;
            strcat(to_frontend, p);
            
            if (right_limit_pos.x==1) //删除一个字符后将会空出一行
            {
                strcat(to_frontend, "\r\n"); //
                strcat(to_frontend, "\x1B[K"); // break
            } 
            else
                strcat(to_frontend, "\x1B[1P"); // delete
            for(i=0; i<strlen(p); i++)
                strcat(to_frontend, "\x08"); // left
        }
        break;
    case CTRL_KEY_BREAK:
        handle_write(console->out, "\r\n", 2);
        cmd_buff[0] = '\0';

        sprintf(to_frontend, "^C");
        break;
    case CTRL_KEY_TAB:
    case CTRL_KEY_OTHER:
        break;
    case CTRL_KEY_NOT:
    default:
        if(buf[len-1] == '\r')
        {
            goto_home(to_frontend);
            
            // add to cmd historys
            cmdh_add(cmd_buff);
            handle_write(console->out, cmd_buff, strlen(cmd_buff));
            handle_write(console->out, "\r\n", 2);
            memset(cmd_buff, 0, MAX_CMD_LENGTH);
        } else {
            if (!poseq(cursor_pos, right_limit_pos)) {
                int i=0;
                char* p = cmd_buff+term_posdiff(&cursor_pos, &left_limit_pos);
                char* newp = cmd_buff+strlen(cmd_buff)-1;
                while(p<=newp) {
                    *(newp+len) = *newp;
                    --newp;
                }
                memcpy(p, buf, len);
                strcpy(to_frontend, p);
                for(i=0;i<(strlen(p)-len);i++)
                    strcat(to_frontend, "\x08");
            } else {
                strncpy(to_frontend, buf, len);
                strncat(cmd_buff, buf, len);
            }

            if (cursor_pos.x == (term_get_cols()-len)) // new line
                strcat(to_frontend, "\r\n");
        }
        break;
    }

    if (to_frontend[0] != 0) {
        from_backend(console->frontend, 0, to_frontend, strlen(to_frontend));
        from_backend_pos(console->frontend, &cursor_pos.x, &cursor_pos.y);
    }

    return 0;
}

