#include "putty.h"
#include "terminal.h"
#include <windows.h>
#include <time.h>

#define PIPE_SIZE (64*1024)

#if 0
typedef struct zprocess_data {
    HANDLE hClientRead, hClientWrite, hServerWrite, hServerRead;
    struct handle *out, *in;
    DWORD dwProcessId;
    void *frontend;
    int bufsize;
} *Zprocess;

BOOL CreateNamedPipePair(PHANDLE hReadPipe, 
                         PHANDLE hWritePipe, 
                         LPSECURITY_ATTRIBUTES lpPipeAttributes, 
                         DWORD nSize);

// send data to server
static void xyz_sentdata(struct handle *h, int new_backlog)
{
    Zprocess console = (Zprocess)handle_get_privdata(h);
    if (new_backlog < 0) {
        const char *error_msg = "Error writing to console device";
//        console_terminate(console);
//        notify_remote_exit(console->frontend);
        logevent(console->frontend, error_msg);
//        connection_fatal(console->frontend, "%s", error_msg);
    } else {
        console->bufsize = new_backlog;
    }
}

// 当对端有数据输出时，调用该函数来处理
static int xyz_gotdata(struct handle *h, void *data, int len)
{
    Zprocess console = (Zprocess)handle_get_privdata(h);
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

        logevent(console->frontend, error_msg);
        return 0;
    } else {
        from_backend(console->frontend, 0, data, len);
        return 0;
    }
}

void xyz_StartSending(Terminal *term)
{
    Zprocess console;
    SECURITY_ATTRIBUTES sa;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	char shellCmd[_MAX_PATH];
    char *prgm;

    // Initial Console struct
    console = snew(struct zprocess_data);
    console->out = console->in = NULL;
    console->bufsize = 0;
    console->dwProcessId = (DWORD)(-1);
    console->frontend=term;
    
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if( !CreateNamedPipePair(&console->hClientRead, &console->hServerWrite, &sa, PIPE_SIZE) ) 
    {
        return "Create pipe1 failed!";
    }
    if( !CreateNamedPipePair(&console->hServerRead, &console->hClientWrite, &sa, PIPE_SIZE) ) 
    {
        return "Create pipe2 failed!";
    }

	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = console->hServerWrite;
	si.hStdError = console->hServerWrite;
	si.hStdInput = console->hServerRead;

{
    char params[1204];
    const char *p;
    char incommand[] = "d:\\puttyplus\\sz.exe";
    char inparams[] = "-b -e -v -y E:\\temp\\INSTALL.txt";
    
    p = incommand + strlen(incommand);
    while (p != incommand) {
        if (*p == '\\' || *p == ' ') { // no space in name either
            p++;
            break;
        }
        p--;
    }
    sprintf(params, "%s %s", p, inparams);
    
    if (!CreateProcess(incommand,params,NULL, NULL,TRUE,CREATE_NEW_CONSOLE, NULL,(conf_get_filename(term->conf, CONF_zdownloaddir))->path,&si,&pi))
//	if( !CreateProcess(NULL, shellCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) )
	{
        return;// "Create process failed!";
	}
    Sleep(100);

    CloseHandle(pi.hThread);
    CloseHandle(console->hServerWrite);
    CloseHandle(console->hServerRead);
}
    console->dwProcessId = pi.dwProcessId;
    
    console->out = handle_output_new(console->hClientWrite, xyz_sentdata, console,
				    HANDLE_FLAG_OVERLAPPED, pi.hProcess);
    console->in = handle_input_new(console->hClientRead, xyz_gotdata, console,
				  HANDLE_FLAG_OVERLAPPED |
				  HANDLE_FLAG_IGNOREEOF, pi.hProcess);

    term->xyz_transfering = 1;
}

void xyz_StartReceive()
{
}

int xyz_ReceiveData(Terminal *term, const u_char *buffer, int len)
{
    return 0;
}

void xyz_Cancel(Terminal *term)
{
}

//void xyz_StartSending(Terminal *term)
//{
//}

void xyz_ReceiveInit(Terminal *term)
{
}

int xyz_Process(Backend *back, void *backhandle, Terminal *term)
{
	return 0;
}
#else
void xyz_updateMenuItems(Terminal *term);

void xyz_ReceiveInit(Terminal *term);
int xyz_ReceiveData(Terminal *term, const u_char *buffer, int len);
static int xyz_SpawnProcess(Terminal *term, const char *incommand, const char *inparams);

#define LSZRZ_OPTIONS       "-b -e -v -y"

#define PIPE_SIZE (64*1024)

struct zModemInternals {
	PROCESS_INFORMATION pi;
	HANDLE read_stdout;
	HANDLE read_stderr;
	HANDLE write_stdin;
};

static int IsWinNT()
{
	OSVERSIONINFO osv;
	osv.dwOSVersionInfoSize = sizeof(osv);
	GetVersionEx(&osv);
	return (osv.dwPlatformId == VER_PLATFORM_WIN32_NT);
}

void xyz_Done(Terminal *term)
{
	if (term->xyz_transfering != 0) {
		term->xyz_transfering = 0;
		xyz_updateMenuItems(term);

		if (term->xyz_Internals) {
			DWORD exitcode = 0;
			CloseHandle(term->xyz_Internals->write_stdin);
			Sleep(500);
			CloseHandle(term->xyz_Internals->read_stdout);
			CloseHandle(term->xyz_Internals->read_stderr);
			GetExitCodeProcess(term->xyz_Internals->pi.hProcess,&exitcode);      //while the process is running
			if (exitcode == STILL_ACTIVE) {
				TerminateProcess(term->xyz_Internals->pi.hProcess, 0);
			}
			sfree(term->xyz_Internals);
			term->xyz_Internals = NULL;
		}
	}
}

static int xyz_Check(Backend *back, void *backhandle, Terminal *term, int outerr);

int xyz_Process(Backend *back, void *backhandle, Terminal *term)
{
	return xyz_Check(back, backhandle, term, 0) + xyz_Check(back, backhandle, term, 1);
}

static int xyz_Check(Backend *back, void *backhandle, Terminal *term, int outerr)
{
	DWORD exitcode = 0;
	DWORD bread, avail;
	char buf[1024];
	HANDLE h;

	if (!term->xyz_transfering) {
		return 0;
	}

	if (outerr) {
		h = term->xyz_Internals->read_stdout;
	} else {
		h = term->xyz_Internals->read_stderr;
	}

	bread = 0;
	PeekNamedPipe(h,buf,1,&bread,&avail,NULL);
	//check to see if there is any data to read from stdout
	if (bread != 0)
	{
		while (1)
		{
			bread = 0;
		
			PeekNamedPipe(h,buf,1,&bread,&avail,NULL);
			if (bread == 0)
				return 0;

			if (ReadFile(h,buf,sizeof(buf),&bread,NULL))  { //read the stdout pipe
				if (bread) {
#if 0
					char *buffer;
					int len;
					
					buffer = buf;
					len = bread;
					if (0)
					{
						char *debugbuff;
						char *bb, *p;
						int i;
						
						debugbuff = _alloca(len*3+128);
						debugbuff[0] = 0;
						bb = debugbuff;
						p = buffer;
						bb += sprintf(bb, "R: %8d   ", time(NULL));
						for(i=0; i < len; i++) {
							bb += sprintf(bb, "%2x ", *p++);
						}
						bb += sprintf(bb, "\n");
						
						OutputDebugString(debugbuff);
					} else {
						char *debugbuff;
						debugbuff = _alloca(len+128);
						memcpy(debugbuff, buffer, len);
						debugbuff[len] = 0;
						if (outerr) {
							strcat(debugbuff, "<<<<<<<\n");
						} else {
							strcat(debugbuff, "<*<*<*<\n");
						}
						OutputDebugString(debugbuff);
					}
#endif
					if (outerr) {
                        // send to server
                        back->send(backhandle, buf, bread);
					} else {
					    // send to front(display)
						from_backend(term, 1, buf, bread);
					}
					continue;
				}
			}
			// EOF/ERROR
			xyz_Done(term);
			return 1;
		}
		return 1;
	}
	
	GetExitCodeProcess(term->xyz_Internals->pi.hProcess,&exitcode);
	if (exitcode != STILL_ACTIVE) {
		xyz_Done(term);
		return 1;
	}

	return 0;
}

void xyz_ReceiveInit(Terminal *term)
{
    char szcmd[MAX_PATH] = "\0";
//	if (xyz_SpawnProcess(term, term->cfg.rzcommand, term->cfg.rzoptions) == 0) {
    {
        char *pp=NULL;
        GetModuleFileName(NULL, szcmd, MAX_PATH);
        pp = strrchr(szcmd, '\\');
        if (pp)
            *(pp+1) = '\0';
        strcat(szcmd, "rz.exe");
    }

	if (xyz_SpawnProcess(term, szcmd, LSZRZ_OPTIONS) == 0) {
		term->xyz_transfering = 1;
	}
}

void xyz_StartSending(Terminal *term)
{
	OPENFILENAME fn;
	char filenames[32000];
	BOOL res;

	memset(&fn, 0, sizeof(fn));
	memset(filenames, 0, sizeof(filenames));
	fn.lStructSize = sizeof(fn);
	fn.lpstrFile = filenames;
	fn.nMaxFile = sizeof(filenames)-1; // the missing -1 was causing a crash on very long selections
	fn.lpstrTitle = "选择要发送的文件...";
	fn.Flags = OFN_ALLOWMULTISELECT | OFN_CREATEPROMPT | OFN_ENABLESIZING | OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST;

	res = GetOpenFileName(&fn);

	if (res)
	{
        char szcmd[MAX_PATH] = "\0";
		char sz_full_params[32767];
		char *p, *curparams;
		p = filenames;

		curparams = sz_full_params;
		sz_full_params[0] = 0;

		curparams += sprintf(curparams, "%s", LSZRZ_OPTIONS);

		if (*(p+strlen(filenames)+1)==0) {
			sprintf(curparams, " \"%s\"", filenames);
		} else {
			for (;;) {
				p=p+strlen(p)+1;
				if (*p==0)
					break;
				curparams += sprintf(curparams, " \"%s\\%s\"", filenames, p);
			}
		}

        {
            char *pp=NULL;
            GetModuleFileName(NULL, szcmd, MAX_PATH);
            pp = strrchr(szcmd, '\\');
            if (pp)
                *(pp+1) = '\0';
            strcat(szcmd, "sz.exe");
        }

		if (xyz_SpawnProcess(term, szcmd, sz_full_params) == 0) {
			term->xyz_transfering = 1;
		}
	}
}

void xyz_Cancel(Terminal *term)
{
	xyz_Done(term);
}

static int xyz_SpawnProcess(Terminal *term, const char *incommand, const char *inparams)
{
	STARTUPINFO si;
	SECURITY_ATTRIBUTES sa;
	SECURITY_DESCRIPTOR sd;               //security information for pipes
	
	HANDLE read_stdout, read_stderr, write_stdin, newstdin, newstdout, newstderr; //pipe handles

	
	
	
	term->xyz_Internals = (struct zModemInternals *)smalloc(sizeof(struct zModemInternals));
	memset(term->xyz_Internals, 0, sizeof(struct zModemInternals));

	if (IsWinNT())        //initialize security descriptor (Windows NT)
	{
		InitializeSecurityDescriptor(&sd,SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
		sa.lpSecurityDescriptor = &sd;
	}
	else sa.lpSecurityDescriptor = NULL;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;         //allow inheritable handles
	
	if (!CreatePipe(&newstdin,&write_stdin,&sa,PIPE_SIZE))   //create stdin pipe
	{
		return 1;
	}
	if (!CreatePipe(&read_stdout,&newstdout,&sa,PIPE_SIZE))  //create stdout pipe
	{
		CloseHandle(newstdin);
		CloseHandle(write_stdin);
		return 1;
	}
	if (!CreatePipe(&read_stderr,&newstderr,&sa,PIPE_SIZE))  //create stdout pipe
	{
		CloseHandle(newstdin);
		CloseHandle(write_stdin);
		CloseHandle(newstdout);
		CloseHandle(read_stdout);
		return 1;
	}

	
	GetStartupInfo(&si);      //set startupinfo for the spawned process
				  /*
				  The dwFlags member tells CreateProcess how to make the process.
				  STARTF_USESTDHANDLES validates the hStd* members. STARTF_USESHOWWINDOW
				  validates the wShowWindow member.
	*/
	si.dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdOutput = newstdout;
	si.hStdError = newstderr;     //set the new handles for the child process
	si.hStdInput = newstdin;

	
	//system
	if (!DuplicateHandle(GetCurrentProcess(), read_stdout, GetCurrentProcess(), &term->xyz_Internals->read_stdout, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		CloseHandle(newstdin);
		CloseHandle(write_stdin);
		CloseHandle(newstdout);
		CloseHandle(read_stdout);
		CloseHandle(newstderr);
		CloseHandle(read_stderr);
		return 1;
	}

	CloseHandle(read_stdout);

	if (!DuplicateHandle(GetCurrentProcess(), read_stderr, GetCurrentProcess(), &term->xyz_Internals->read_stderr, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		CloseHandle(newstdin);
		CloseHandle(newstdout);
		CloseHandle(read_stdout);
		CloseHandle(write_stdin);
		CloseHandle(newstderr);
		CloseHandle(read_stderr);
		return 1;
	}

	CloseHandle(read_stderr);

	if (!DuplicateHandle(GetCurrentProcess(), write_stdin, GetCurrentProcess(), &term->xyz_Internals->write_stdin, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		CloseHandle(newstdin);
		CloseHandle(write_stdin);
		CloseHandle(newstdout);
		CloseHandle(term->xyz_Internals->read_stdout);
		CloseHandle(newstderr);
		CloseHandle(term->xyz_Internals->read_stderr);
		return 1;
	}

	CloseHandle(write_stdin);
	
	//spawn the child process
	{
		char params[1204];
		const char *p;

		p = incommand + strlen(incommand);
		while (p != incommand) {
			if (*p == '\\' || *p == ' ') { // no space in name either
				p++;
				break;
			}
			p--;
		}
		sprintf(params, "%s %s", p, inparams);

		if (!CreateProcess(incommand,params,NULL, NULL,TRUE,CREATE_NEW_CONSOLE, NULL,(conf_get_filename(term->conf, CONF_zdownloaddir))->path,&si,&term->xyz_Internals->pi))
		{
			DWORD err = GetLastError();
	//		ErrorMessage("CreateProcess");
			CloseHandle(newstdin);
			CloseHandle(term->xyz_Internals->write_stdin);
			CloseHandle(newstdout);
			CloseHandle(term->xyz_Internals->read_stdout);
			CloseHandle(newstderr);
			CloseHandle(term->xyz_Internals->read_stderr);
			return 1;
		}
	}

	CloseHandle(newstdin);
	CloseHandle(newstdout);
	CloseHandle(newstderr);

	return 0;
}

int xyz_ReceiveData(Terminal *term, const u_char *buffer, int len)
{
	DWORD written;
#if 0
	if (0)
	{
		char *debugbuff;
		char *bb, *p;
		int i;

		debugbuff = _alloca(len*3+128);
		debugbuff[0] = 0;
		bb = debugbuff;
		p = buffer;
		bb += sprintf(bb, "R: %8d   ", time(NULL));
		for(i=0; i < len; i++) {
			bb += sprintf(bb, "%2x ", *p++);
		}
		bb += sprintf(bb, "\n");

		OutputDebugString(debugbuff);
	} else {
		char *debugbuff;
		debugbuff = _alloca(len+128);
		memcpy(debugbuff, buffer, len);
		debugbuff[len] = 0;
		strcat(debugbuff, ">>>>>>>\n");
		OutputDebugString(debugbuff);
	}
#endif
	WriteFile(term->xyz_Internals->write_stdin,buffer,len,&written,NULL);

	return 0 ;
}
#endif

/*
    0  - not lszrz
    1  - remote sz
    2  - remote rz
 */
int xyz_is_lszrz_cmd(const char* data, int len)
{
    int ret = 0;
    
    if (len == 21){
        if (!memcmp(data, "**\30B0", 5) && !memcmp(data+18, "\x0d\x8a\x11", 3))
        {
            if(data[5]=='0'){
                // remote sz
                logevent(NULL, "remote sz");
                ret = 1;
            } else if (data[5]=='1') {
                // remote rz
                logevent(NULL, "remote rz");
                ret = 2;
            }
        }
    } else if(len==24){
        if (!memcmp(data, "rz\r**\30B00", 9) && !memcmp(data+21, "\x0d\x8a\x11", 3))
        {
            // remote sz
            logevent(NULL, "remote sz");
            ret = 1;
        }
    } else if(len==43){
        if (!memcmp(data, "rz waiting to receive.**\30B01", 28) && !memcmp(data+40, "\x0d\x8a\x11", 3))
        {
            // remote rz
            logevent(NULL, "remote rz");
            ret = 2;
        }
    }

    return ret;
}

