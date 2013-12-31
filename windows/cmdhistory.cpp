#include "linklist.h"
#include "cmdhistory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int left_limit_x, left_limit_y;
int right_limit_x, right_limit_y;

#define MAX_CMD_LENGTH  8192
static CLinkedList cmdlst;
static int cmd_exec_flag;
static char cmd_buf[MAX_CMD_LENGTH];
static int new_cmd_buf;

void cmdh_init()
{
    cmd_exec_flag = 1;
    new_cmd_buf = 0;
    memset(cmd_buf, 0, MAX_CMD_LENGTH);
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
    int cmd_len = strlen(cmd); //去除 \r\n
    
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

enum{
    CMD_KEY_NORMAL = 0,
    CMD_KEY_INVALID,
    CMD_KEY_UP,
    CMD_KEY_DOWN,
    CMD_KEY_RIGHT,
    CMD_KEY_LEFT,
    CMD_KEY_HOME,
    CMD_KEY_END,
    CMD_KEY_DELETE,
    CMD_KEY_BACKSPACE,
};

static int key_translate(const char *key, int len)
{
    int result = CMD_KEY_NORMAL;
    
    if( !strncmp("\x1B[A", key, len) )
    {// UP
        result = CMD_KEY_UP;
    }
    else if( !strncmp("\x1B[B", key, len) )
    {// DOWN
        result = CMD_KEY_DOWN;
    }
    else if( !strncmp("\x1B[C", key, len) )
    {// RIGHT
        result = CMD_KEY_RIGHT;
    }
    else if( !strncmp("\x1B[D", key, len) )
    {// LEFT
        result = CMD_KEY_LEFT;
    }
    else if( !strncmp("\x1B[1~", key, len) )
    {// HOME
        result = CMD_KEY_HOME;
    }
    else if( !strncmp("\x1B[4~", key, len) )
    {// END
        result = CMD_KEY_END;
    }
    else if( !strncmp("\x1B[3~", key, len) )
    {// DELETE
        result = CMD_KEY_DELETE;
    }
    else if( !strncmp("\x7F", key, len) )
    {// BACKSPACE
        result = CMD_KEY_BACKSPACE;
    }
    
    return result;
}

//extern "C" int left_limit_x, left_limit_y;
//extern "C" int right_limit_x, right_limit_y;

static int insert_backspace(char* buf, int count)
{
    int i=0;
    char tmp_buf[MAX_CMD_LENGTH];
    strcpy(tmp_buf, buf);
    memset(buf,0,MAX_CMD_LENGTH);
    for(i=0; i<count; i++)
        buf[i] = '\x08';
    buf[i] = '\0';
    strcat(buf, tmp_buf);
    return 0;
}

void cmd_add_char(const char *buf, int len, const char**show, const char**send)
{
    int key_s = 0;
    if(new_cmd_buf)
    {
        cmd_buf[0] = 0;
        new_cmd_buf = 0;
    }
    
    switch( key_s=key_translate(buf, len) )
    {
    case CMD_KEY_UP:
    case CMD_KEY_DOWN:
/*
        *show = cmdh_get( (key_s==CMD_KEY_UP)?1:0 );
        if(*show)
        {
            int bs_count = strlen(cmd_buf);
            cmd_buf[0] = 0;
            strcat(cmd_buf, *show);
            if (bs_count)
                insert_backspace((char*)*show, bs_count);
        }
*/
        break;
    case CMD_KEY_BACKSPACE:
        cmd_buf[strlen(cmd_buf)-1] = '\0';
    case CMD_KEY_LEFT:
        if (right_limit_y>=left_limit_y && right_limit_x>left_limit_x)
            *show = buf;
        break;
    case CMD_KEY_RIGHT:
        if (right_limit_y>=left_limit_y && right_limit_x>left_limit_x)
            *show = buf;
        break;
    case CMD_KEY_NORMAL:
        *show = buf;
        strncat(cmd_buf, buf, len);
        break;
    default:
        break;
    }
    
    if( buf[0] == '\r' )
    {
        // 将执行的命令加入命令历史记录
        cmd_buf[strlen(cmd_buf)-1] = '\0';
        cmdh_add(cmd_buf);

        strcat(cmd_buf, "\r\n");
        *send = cmd_buf;
        *show = cmd_buf+strlen(cmd_buf)-2;

        new_cmd_buf = 1;
    }
}


