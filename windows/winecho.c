/*
 * Echo back end (Windows-specific).
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "putty.h"

typedef struct echo_backend_data {
    HANDLE hRead, hWrite;
    struct handle *out, *in;
    void *frontend;
    int bufsize;
} *Echo;

static void echo_terminate(Echo echo)
{
    if (echo->out) {
    	handle_free(echo->out);
    	echo->out = NULL;
    }
    if (echo->in) {
    	handle_free(echo->in);
    	echo->in = NULL;
    }
    if (echo->hWrite != INVALID_HANDLE_VALUE) {
    	CloseHandle(echo->hWrite);
    	echo->hWrite = INVALID_HANDLE_VALUE;
    }
    if (echo->hRead != INVALID_HANDLE_VALUE) {
    	CloseHandle(echo->hRead);
    	echo->hRead = INVALID_HANDLE_VALUE;
    }
}

static int echo_gotdata(struct handle *h, void *data, int len)
{
    Echo echo = (Echo)handle_get_privdata(h);
    if (len <= 0) {
        const char *error_msg;
    	/*
    	 * Currently, len==0 should never happen because we're
    	 * ignoring EOFs. However, it seems not totally impossible
    	 * that this same back end might be usable to talk to named
    	 * pipes or some other non-echo device, in which case EOF
    	 * may become meaningful here.
    	 */
        if (len == 0)
            error_msg = "End of file reading from echo device";
        else
            error_msg = "Error reading from echo device";

        echo_terminate(echo);
        notify_remote_exit(echo->frontend);
        logevent(echo->frontend, error_msg);
        connection_fatal(echo->frontend, "%s", error_msg);
        return 0;
    } else {
        return from_backend(echo->frontend, 0, data, len);
    }
}

static void echo_sentdata(struct handle *h, int new_backlog)
{
    Echo echo = (Echo)handle_get_privdata(h);
    if (new_backlog < 0) {
        const char *error_msg = "Error writing to echo device";
        echo_terminate(echo);
        notify_remote_exit(echo->frontend);
        logevent(echo->frontend, error_msg);
        connection_fatal(echo->frontend, "%s", error_msg);
    } else {
        echo->bufsize = new_backlog;
    }
}

/*
 * Called to set up the echo connection.
 * 
 * Returns an error message, or NULL on success.
 *
 * Also places the canonical host name into `realhost'. It must be
 * freed by the caller.
 */
static const char *echo_init(void *frontend_handle, void **backend_handle,
			       Conf *conf, char *host, int port,
			       char **realhost, int nodelay, int keepalive)
{
    Echo echo;
    SECURITY_ATTRIBUTES sa;
    HANDLE  hRead,hWrite;
    
    echo = snew(struct echo_backend_data);
    echo->out = echo->in = NULL;
    echo->bufsize = 0;
    *backend_handle = echo;
    echo->frontend = frontend_handle;
    
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if( !CreatePipe(&hRead,&hWrite,&sa,0) ) 
    { 
        return "Create pipe failed!";
    }
    echo->hRead = hRead;
    echo->hWrite = hWrite;
    echo->out = handle_output_new(hWrite, echo_sentdata, echo,
				    HANDLE_FLAG_OVERLAPPED);
    echo->in = handle_input_new(hRead, echo_gotdata, echo,
				  HANDLE_FLAG_OVERLAPPED |
				  HANDLE_FLAG_IGNOREEOF |
				  HANDLE_FLAG_UNITBUFFER);
    
    *realhost = dupstr("ECHO");
    update_specials_menu(echo->frontend);

    return NULL;
}

static void echo_free(void *handle)
{
    Echo echo = (Echo) handle;
    echo_terminate(echo);
    expire_timer_context(echo);
    sfree(echo);
}

static void echo_reconfig(void *handle, Conf *conf)
{
}

/*
 * Called to send data down the echo connection.
 */
static int echo_send(void *handle, char *buf, int len)
{
    Echo echo = (Echo) handle;

    if (echo->out == NULL)
    	return 0;

    if(buf[len-1] == '\r')
    {
        buf[len] = '\n';
        buf[len+1] = 0;
        ++len;
    }
    
    echo->bufsize = handle_write(echo->out, buf, len);
    return echo->bufsize;
}

/*
 * Called to query the current sendability status.
 */
static int echo_sendbuffer(void *handle)
{
    Echo echo = (Echo) handle;
    return echo->bufsize;
}

/*
 * Called to set the size of the window
 */
static void echo_size(void *handle, int width, int height)
{
    /* Do nothing! */
    return;
}

/*
 * Send echo special codes.
 */
static void echo_special(void *handle, Telnet_Special code)
{
    return;
}

/*
 * Return a list of the special codes that make sense in this
 * protocol.
 */
static const struct telnet_special *echo_get_specials(void *handle)
{
    static const struct telnet_special specials[] = {
	{NULL, TS_EXITMENU}
    };
    return specials;
}

static int echo_connected(void *handle)
{
    return 1;			       /* always connected */
}

static int echo_sendok(void *handle)
{
    return 1;
}

static void echo_unthrottle(void *handle, int backlog)
{
    Echo echo = (Echo) handle;
    if (echo->in)
	handle_unthrottle(echo->in, backlog);
}

static int echo_ldisc(void *handle, int option)
{
    /*
     * Local editing and local echo are off by default.
     */
    return 0;
}

static void echo_provide_ldisc(void *handle, void *ldisc)
{
    /* This is a stub. */
}

static void echo_provide_logctx(void *handle, void *logctx)
{
    /* This is a stub. */
}

static int echo_exitcode(void *handle)
{
    Echo echo = (Echo) handle;
    if (echo->hWrite != INVALID_HANDLE_VALUE
        || echo->hRead != INVALID_HANDLE_VALUE)
        return -1;                     /* still connected */
    else
        /* Exit codes are a meaningless concept with echo ports */
        return INT_MAX;
}

/*
 * cfg_info for Echo does nothing at all.
 */
static int echo_cfg_info(void *handle)
{
    return 0;
}

Backend echo_backend = {
    echo_init,
    echo_free,
    echo_reconfig,
    echo_send,
    echo_sendbuffer,
    echo_size,
    echo_special,
    echo_get_specials,
    echo_connected,
    echo_exitcode,
    echo_sendok,
    echo_ldisc,
    echo_provide_ldisc,
    echo_provide_logctx,
    echo_unthrottle,
    echo_cfg_info,
    "echo",
    PROT_ECHO,
    0
};
