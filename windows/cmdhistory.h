#ifndef __CMD_HISTORY_H__
#define __CMD_HISTORY_H__

#ifdef __cplusplus
extern "C" {
#endif

void cmdh_init();
void cmdh_free();
void cmdh_add(const char* cmd);
const char* cmdh_get(int up);
void cmd_add_char(const char *buf, int len, const char**show, const char**send);

#ifdef __cplusplus
}
#endif

#endif
