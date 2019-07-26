#ifndef _PCS_SHELL_SHELL_H_
#define _PCS_SHELL_SHELL_H_

#include <time.h>
#include "utils.h"
#include "pcs/pcs.h"

#define SORT_DIRECTION_ASC	0 /*正序*/
#define SORT_DIRECTION_DESC 1 /*倒序*/

#define CURSOR_UP    0x41
#define CURSOR_DOWN  0x42
#define CURSOR_RIGHT 0x43
#define CURSOR_LEFT  0x44

#define CURSOR_HOME  0x48
#define CURSOR_END   0x4B


#define BEL 0x07
#define BS  0x08
#define HT  0x09
#define LF  0x0a
#define CR  0x0d
#define ESC 0x1b
#define DEL 0x7f

/* other macro */
#define MAX_CMD_LEN      (64)
#define MAX_CMD_HISTORY_LEN 20
#define MAX_WORD_LEN        64

/* shell context */
typedef struct shellContext
{
	char		*context_path; /*上下文文件的路径*/
	char		*cookie_path; /*Cookie文件路径*/
	char		*captcha_path; /*验证码图片路径*/
	char		*workDir; /*当前工作目录*/
	Pcs			pcs;

	int			list_page_size; /*执行list命令时，每页大小*/
	char		*list_sort_name; /*执行list命令时，排序字段，可选值：name|time|size*/
	char		*list_sort_direction; /*执行list命令时，排序字段，可选值：asc|desc*/

	char		*secure_method; /*加密方法，可选值：plaintext|aes-cbc-128|aes-cbc-192|aes-cbc-256*/
	char		*secure_key;    /*加密时的KEY*/
	int			secure_enable;  /*是否启用加密*/

	int			timeout_retry;  /*是否启用超时后重试*/
	int			max_thread; /*指定最大线程数量*/
	int			max_speed_per_thread; /*指定单个线程的最多下载速度*/
	int			max_upload_speed_per_thread; /*指定单个线程的最大上传速度*/
	int			cache_size; /* 磁盘缓存的大小 */
	char		*user_agent;    /**/
} shellContext;

struct {
    u32 idx;
    u32 len;
    u32 scroll;
    struct {
            u32  cmd_len;
            char cmd[MAX_CMD_LEN];
        } buf[MAX_CMD_HISTORY_LEN];
} cmd_history;

const char *context_path();
const char *cookie_path();
const char *captcha_path();
char *context2str(shellContext *context);
Pcs *create_pcs(shellContext *context);
void destroy_pcs(Pcs *pcs);

extern u8 suspended;
#endif
