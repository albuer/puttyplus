/*
 * Console back end (Windows-specific).
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "putty.h"

typedef struct console_backend_data {
    HANDLE hRead, hWrite;
    struct handle *out, *in;
    void *frontend;
    int bufsize;
} *Console;

static void console_terminate(Console console)
{
    if (console->out) {
    	handle_free(console->out);
    	console->out = NULL;
    }
    if (console->in) {
    	handle_free(console->in);
    	console->in = NULL;
    }
    if (console->hWrite != INVALID_HANDLE_VALUE) {
    	CloseHandle(console->hWrite);
    	console->hWrite = INVALID_HANDLE_VALUE;
    }
    if (console->hRead != INVALID_HANDLE_VALUE) {
    	CloseHandle(console->hRead);
    	console->hRead = INVALID_HANDLE_VALUE;
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
    HANDLE  hClientRead,hServerWrite;
    HANDLE  hClientWrite,hServerRead;
static const char *console_init(void *frontend_handle, void **backend_handle,
			       Conf *conf, char *host, int port,
			       char **realhost, int nodelay, int keepalive)
{
    Console console;
    SECURITY_ATTRIBUTES sa;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
    
    console = snew(struct console_backend_data);
    console->out = console->in = NULL;
    console->bufsize = 0;
    *backend_handle = console;
    console->frontend = frontend_handle;
    
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
	si.wShowWindow = SW_HIDE;   
	si.hStdOutput = hServerWrite;
	si.hStdError = hServerWrite;
	si.hStdInput = hServerRead;

	if( !CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi) )
	{
        return "Create process failed!";
	}
//    CloseHandle(hServerRead);
//    CloseHandle(hServerWrite);
    
    console->hRead = hClientRead;
    console->hWrite = hClientWrite;
    console->out = handle_output_new(console->hWrite, console_sentdata, console,
				    HANDLE_FLAG_OVERLAPPED);
    console->in = handle_input_new(console->hRead, console_gotdata, console,
				  HANDLE_FLAG_OVERLAPPED |
				  HANDLE_FLAG_IGNOREEOF |
				  HANDLE_FLAG_UNITBUFFER);
    
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

/*
 * Called to send data down the console connection.
 */
static int console_send(void *handle, char *buf, int len)
{
    Console console = (Console) handle;
    int ret = 0;

    if (console->out == NULL)
    	return 0;

    if(buf[len-1] == '\r')
    {
        buf[len] = '\n';
        buf[len+1] = 0;
        ++len;
    }

//	WriteFile(hServerWrite, buf, len, &ret, NULL);
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
