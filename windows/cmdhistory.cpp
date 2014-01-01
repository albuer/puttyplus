#include "linklist.h"
#include "cmdhistory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static CLinkedList cmdlst;
static int cmd_exec_flag;

void cmdh_init()
{
    cmd_exec_flag = 1;
    return;
}

void cmdh_free()
{
    void *pdata = NULL;
    while( pdata = cmdlst.RemoveFirst() )
        free(pdata);
}

void cmdh_add(const char* cmd)
{
    const char* last_cmd = (const char*)cmdlst.GetLast();
    int cmd_len = strlen(cmd); //È¥³ý \r\n

    if(cmd_len<=0)return;
    
    if( last_cmd == NULL || _stricmp(last_cmd, cmd) )
    {
        void* pdata = malloc(cmd_len+1);
        memcpy(pdata, cmd, cmd_len);
        ((char*)pdata)[cmd_len] = 0;
        
        cmdlst.Append(pdata);
        {
            const char* cur_cmd = (const char*)cmdlst.GetCurrent();
            if( strcmp((const char*)pdata, cur_cmd) )
                cmdlst.SetCurToTail();
        }
    }

    cmd_exec_flag = 1;
}

const char* cmdh_get(int up)
{
    const char* cmd = NULL;
    if( cmdlst.IsEmpty() )
    {
        return NULL;
    }

    if(up)
    {
        if(cmd_exec_flag)
        {
            cmd = (const char*)cmdlst.GetCurrent();
        }
        else
        {
            cmd = (const char*)cmdlst.GetPrev();
        }
    }
    else
    {
        cmd = (const char*)cmdlst.GetNext();
    }
    
    cmd_exec_flag = 0;

    return cmd;
}

