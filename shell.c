#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <locale.h>
#include <signal.h>
#include <termios.h>

#include <sys/file.h>
#include <sys/select.h>
#include <ctype.h>
#ifdef WITH_READLINE
#include <readline/readline.h>
#ifdef HAVE_READLINE_HISTORY_H
#include <readline/history.h>
#endif
#endif

#include "utils.h"
#include "arg.h"
#include "cmd.h"
#include "cache.h"
#include "shell.h"
#include "pcs/cJSON.h"

#define TIMEOUT     5       /* secs between rexmt's */
#define LBUFLEN     200     /* size of input buffer */

#ifdef WITH_READLINE
char *line = NULL;
#else
char line[LBUFLEN];
#endif
int margc;
char *margv[20];
//sigjmp_buf toplevel;
void intr(int);

void get(int, char **);
void help(int, char **);
void modecmd(int, char **);
void put(int, char **);
void quit(int, char **);
void setascii(int, char **);
void setbinary(int, char **);
void setpeer(int, char **);
void setrexmt(int, char **);
void settimeout(int, char **);
void settrace(int, char **);
void setverbose(int, char **);
void status(int, char **);
void setliteral(int, char **);

static void interactive_command(struct shellContext *);

static void getusage(char *);
static void makeargv(void);
static void putusage(char *);

#define HELPINDENT (sizeof("connect"))

struct cli_cmd_t *getcmd(char *name);

char *tail(char *);
char *xstrdup(const char *);



const char *program;
static char cmd_buf[MAX_CMD_LEN];
static u32  cmd_len = 0;
static u32  cmd_cursor = 0;
static struct termios stored_settings;

//const char *prompt = "baiduPcs> ";

u8 suspended = 1;

#pragma region 初始化相关函数

/*hood cJSON 库中分配内存的方法，用于检查内存泄漏*/
void hook_cjson()
{
	cJSON_Hooks hooks = { 0 };
#if defined(DEBUG) || defined(_DEBUG)
	hooks.malloc_fn = &pcs_mem_malloc_arg1;
	hooks.free_fn = &pcs_mem_free;
#else

#endif
	cJSON_InitHooks(&hooks);
}

/*把上下文转换为字符串*/
char *context2str(shellContext *context)
{
	char *json;
	cJSON *root, *item;

	root = cJSON_CreateObject();
	assert(root);

	item = cJSON_CreateString(context->cookie_path);
	assert(item);
	cJSON_AddItemToObject(root, "cookie_path", item);

	item = cJSON_CreateString(context->captcha_path);
	assert(item);
	cJSON_AddItemToObject(root, "captcha_path", item);

	item = cJSON_CreateString(context->workDir);
	assert(item);
	cJSON_AddItemToObject(root, "workDir", item);

	item = cJSON_CreateNumber((double)context->list_page_size);
	assert(item);
	cJSON_AddItemToObject(root, "list_page_size", item);

	item = cJSON_CreateString(context->list_sort_name);
	assert(item);
	cJSON_AddItemToObject(root, "list_sort_name", item);

	item = cJSON_CreateString(context->list_sort_direction);
	assert(item);
	cJSON_AddItemToObject(root, "list_sort_direction", item);

	item = cJSON_CreateString(context->secure_method);
	assert(item);
	cJSON_AddItemToObject(root, "secure_method", item);

	item = cJSON_CreateString(context->secure_key);
	assert(item);
	cJSON_AddItemToObject(root, "secure_key", item);

	item = cJSON_CreateBool(context->secure_enable);
	assert(item);
	cJSON_AddItemToObject(root, "secure_enable", item);

	item = cJSON_CreateBool(context->timeout_retry);
	assert(item);
	cJSON_AddItemToObject(root, "timeout_retry", item);

	item = cJSON_CreateNumber(context->max_thread);
	assert(item);
	cJSON_AddItemToObject(root, "max_thread", item);

	item = cJSON_CreateNumber(context->max_speed_per_thread);
	assert(item);
	cJSON_AddItemToObject(root, "max_speed_per_thread", item);

	item = cJSON_CreateNumber(context->max_upload_speed_per_thread);
	assert(item);
	cJSON_AddItemToObject(root, "max_upload_speed_per_thread", item);

	item = cJSON_CreateString(context->user_agent);
	assert(item);
	cJSON_AddItemToObject(root, "user_agent", item);

	item = cJSON_CreateNumber(context->cache_size);
	assert(item);
	cJSON_AddItemToObject(root, "cache_size", item);

	json = cJSON_Print(root);
	assert(json);

	cJSON_Delete(root);
	return json;
}

#pragma region 获取默认路径

/*获取上下文存储文件路径*/
const char *context_path()
{
	static char filename[1024] = { 0 };
	char *env_value = getenv(PCS_CONTEXT_ENV);
	if (env_value) return env_value;
	if (!filename[0]) {
#ifdef WIN32
		strcpy(filename, getenv("UserProfile"));
		strcat(filename, "\\.pcs");
		CreateDirectoryRecursive(filename);
		strcat(filename, "\\pcs.context");
#else
		strcpy(filename, getenv("HOME"));
		strcat(filename, "/.pcs");
		CreateDirectoryRecursive(filename);
		strcat(filename, "/pcs.context");
#endif
	}
	return filename;
}

/*返回COOKIE文件路径*/
const char *cookie_path()
{
	static char filename[1024] = { 0 };
	char *env_value = getenv(PCS_COOKIE_ENV);
	if (env_value) return env_value;
	if (!filename[0]){ /*如果已经处理过，则直接返回*/
#ifdef WIN32
		strcpy(filename, getenv("UserProfile"));
		strcat(filename, "\\.pcs");
		CreateDirectoryRecursive(filename);
		strcat(filename, "\\");
		strcat(filename, "default.cookie");
#else
		strcpy(filename, getenv("HOME"));
		strcat(filename, "/.pcs");
		CreateDirectoryRecursive(filename);
		strcat(filename, "/");
		strcat(filename, "default.cookie");
#endif
	}
	return filename;
}

/*返回验证码图片文件路径*/
const char *captcha_path()
{
	static char filename[1024] = { 0 };
	char *env_value = getenv(PCS_CAPTCHA_ENV);
	if (env_value) return env_value;
	if (!filename[0]){ /*如果已经处理过，则直接返回*/
#ifdef WIN32
		strcpy(filename, getenv("UserProfile"));
		strcat(filename, "\\.pcs");
		CreateDirectoryRecursive(filename);
		strcat(filename, "\\");
		strcat(filename, "captcha.gif");
#else
		strcpy(filename, getenv("HOME"));
		strcat(filename, "/.pcs");
		CreateDirectoryRecursive(filename);
		strcat(filename, "/");
		strcat(filename, "captcha.gif");
#endif
	}
	return filename;
}

#pragma endregion


/*保存上下文*/
void save_context(shellContext *context)
{
	const char *filename;
	char *json;
	FILE *pf;

	json = context2str(context);
	assert(json);

	filename = context->context_path;
	pf = fopen(filename, "wb");
	if (!pf) {
		fprintf(stderr, "Error: Can't open the file: %s\n", filename);
		pcs_free(json);
		return;
	}
	fwrite(json, 1, strlen(json), pf);
	fclose(pf);
	pcs_free(json);
}

/*还原保存的上下文。
成功返回0，失败返回非0值。*/
int restore_context(shellContext *context, const char *filename)
{
	char *filecontent = NULL;
	int filesize = 0;
	cJSON *root, *item;

	if (!filename) {
		filename = context->context_path;
	}
	else {
		if (context->context_path) pcs_free(context->context_path);
#ifdef WIN32
		context->context_path = pcs_utils_strdup(filename);
#else
		/* Can't open the path that start with '~/'. why? It's not good, but work. */
		if (filename[0] == '~' && filename[1] == '/') {
			static char tmp[1024] = { 0 };
			strcpy(tmp, getenv("HOME"));
			strcat(tmp, filename + 1);
			context->context_path = pcs_utils_strdup(tmp);
		}
		else {
			context->context_path = pcs_utils_strdup(filename);
		}
#endif
	}
	filesize = read_file(context->context_path, &filecontent);
	if (filesize <= 0) {
		fprintf(stderr, "Error: Can't read the context file (%s).\n", context->context_path);
		if (filecontent) pcs_free(filecontent);
		return -1;
	}
	root = cJSON_Parse(filecontent);
	if (!root) {
		fprintf(stderr, "Error: Broken context file (%s).\n", context->context_path);
		pcs_free(filecontent);
		return -1;
	}

	item = cJSON_GetObjectItem(root, "cookie_path");
	if (item && item->valuestring && item->valuestring[0]) {
		if (!is_absolute_path(item->valuestring)) {
			printf("warning: Invalid context.cookie_path, the value should be absolute path, use default value: %s.\n", context->cookie_path);
		}
		else {
			if (context->cookie_path) pcs_free(context->cookie_path);
			context->cookie_path = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "captcha_path");
	if (item && item->valuestring && item->valuestring[0]) {
		if (!is_absolute_path(item->valuestring)) {
			printf("warning: Invalid context.captcha_path, the value should be absolute path, use default value: %s.\n", context->captcha_path);
		}
		else {
			if (context->captcha_path) pcs_free(context->captcha_path);
			context->captcha_path = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "workDir");
	if (item && item->valuestring && item->valuestring[0]) {
		if (item->valuestring[0] != '/') {
			printf("warning: Invalid context.workDir, the value should be absolute path, use default value: %s.\n", context->workDir);
		}
		else {
			if (context->workDir) pcs_free(context->workDir);
			context->workDir = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "list_page_size");
	if (item) {
		if (((int)item->valueint) < 1) {
			printf("warning: Invalid context.list_page_size, the value should be great than 0, use default value: %d.\n", context->list_page_size);
		}
		else {
			context->list_page_size = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "list_sort_name");
	if (item && item->valuestring && item->valuestring[0]) {
		if (strcmp(item->valuestring, "name") && strcmp(item->valuestring, "time") && strcmp(item->valuestring, "size")) {
			printf("warning: Invalid context.list_sort_name, the value should be one of [name|time|size], use default value: %s.\n", context->list_sort_name);
		}
		else {
			if (context->list_sort_name) pcs_free(context->list_sort_name);
			context->list_sort_name = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "list_sort_direction");
	if (item && item->valuestring && item->valuestring[0]) {
		if (strcmp(item->valuestring, "asc") && strcmp(item->valuestring, "desc")) {
			printf("warning: Invalid context.list_sort_direction, the value should be one of [asc|desc], use default value: %s.\n", context->list_sort_direction);
		}
		else {
			if (context->list_sort_direction) pcs_free(context->list_sort_direction);
			context->list_sort_direction = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "secure_method");
	if (item && item->valuestring && item->valuestring[0]) {
		if (strcmp(item->valuestring, "plaintext") && strcmp(item->valuestring, "aes-cbc-128") && strcmp(item->valuestring, "aes-cbc-192") && strcmp(item->valuestring, "aes-cbc-256")) {
			printf("warning: Invalid context.secure_method, the value should be one of [plaintext|aes-cbc-128|aes-cbc-192|aes-cbc-256], use default value: %s.\n", context->secure_method);
		}
		else {
			if (context->secure_method) pcs_free(context->secure_method);
			context->secure_method = pcs_utils_strdup(item->valuestring);
		}
	}

	item = cJSON_GetObjectItem(root, "secure_key");
	if (item && item->valuestring && item->valuestring[0]) {
		if (context->secure_key) pcs_free(context->secure_key);
		context->secure_key = pcs_utils_strdup(item->valuestring);
	}

	item = cJSON_GetObjectItem(root, "secure_enable");
	if (item) {
		context->secure_enable = item->valueint ? 1 : 0;
	}

	item = cJSON_GetObjectItem(root, "timeout_retry");
	if (item) {
		context->timeout_retry = item->valueint ? 1 : 0;
	}

	item = cJSON_GetObjectItem(root, "max_thread");
	if (item) {
		if (((int)item->valueint) < 1) {
			printf("warning: Invalid context.max_thread, the value should be great than 0, use default value: %d.\n", context->max_thread);
		}
		else {
			context->max_thread = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "max_speed_per_thread");
	if (item) {
		if (((int)item->valueint) < 0) {
			printf("warning: Invalid context.max_speed_per_thread, the value should be >= 0, use default value: %d.\n", context->max_speed_per_thread);
		}
		else {
			context->max_speed_per_thread = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "max_upload_speed_per_thread");
	if (item) {
		if (((int)item->valueint) < 0) {
			printf("warning: Invalid context.max_upload_speed_per_thread, the value should be >= 0, use default value: %d.\n", context->max_upload_speed_per_thread);
		}
		else {
			context->max_upload_speed_per_thread = (int)item->valueint;
		}
	}

	item = cJSON_GetObjectItem(root, "user_agent");
	if (item && item->valuestring && item->valuestring[0]) {
		if (context->user_agent) pcs_free(context->user_agent);
		context->user_agent = pcs_utils_strdup(item->valuestring);
	}

	item = cJSON_GetObjectItem(root, "cache_size");
	if (item) {
		if (((int)item->valueint) < 0) {
			printf("warning: Invalid context.cache_size, the value should be >= 0, use default value: %d.\n", context->cache_size);
		}
		else {
			context->cache_size = (int)item->valueint;
		}
	}

	cJSON_Delete(root);
	pcs_free(filecontent);
	return 0;
}

/*初始化上下文*/
void init_context(shellContext *context, struct args *arg)
{
	memset(context, 0, sizeof(shellContext));
	context->context_path = pcs_utils_strdup(context_path());
	context->cookie_path = pcs_utils_strdup(cookie_path());
	context->captcha_path = pcs_utils_strdup(captcha_path());
	context->workDir = pcs_utils_strdup("/");
	context->list_page_size = PRINT_PAGE_SIZE;
	context->list_sort_name = pcs_utils_strdup("name");
	context->list_sort_direction = pcs_utils_strdup("asc");
	
	context->secure_method = pcs_utils_strdup("plaintext");
	context->secure_key = pcs_utils_strdup("");
	context->secure_enable = 0;

	context->timeout_retry = 1;
	context->max_thread = DEFAULT_THREAD_NUM;
	context->max_speed_per_thread = 0;
	context->max_upload_speed_per_thread = 0;
	context->cache_size = MAX_CACHE_SIZE;
    context->pcs = NULL;

	context->user_agent = pcs_utils_strdup(USAGE);
}

/*释放上下文*/
void free_context(shellContext *context)
{
	if (context->cookie_path) pcs_free(context->cookie_path);
	if (context->captcha_path) pcs_free(context->captcha_path);
	if (context->workDir) pcs_free(context->workDir);
	if (context->list_sort_name) pcs_free(context->list_sort_name);
	if (context->list_sort_direction) pcs_free(context->list_sort_direction);
	if (context->secure_method) pcs_free(context->secure_method);
	if (context->secure_key) pcs_free(context->secure_key);
	if (context->context_path) pcs_free(context->context_path);
	if (context->user_agent) pcs_free(context->user_agent);
	memset(context, 0, sizeof(shellContext));
}

/*初始化PCS*/
Pcs *create_pcs(shellContext *context)
{
	Pcs *pcs = pcs_create(context->cookie_path);
	if (!pcs) return NULL;
	pcs_setopt(pcs, PCS_OPTION_CAPTCHA_FUNCTION, (void *)&verifycode);
	pcs_setopt(pcs, PCS_OPTION_CAPTCHA_FUNCTION_DATA, (void *)context);
    pcs_setopt(pcs, PCS_OPTION_INPUT_FUNCTION, (void *)&input_str);
    pcs_setopt(pcs, PCS_OPTION_INPUT_FUNCTION_DATA, (void *)context);
	pcs_setopts(pcs,
		PCS_OPTION_PROGRESS_FUNCTION, (void *)&upload_progress,
		PCS_OPTION_PROGRESS, (void *)((long)pcsFalse),
		PCS_OPTION_USAGE, (void*)context->user_agent,
		//PCS_OPTION_TIMEOUT, (void *)((long)TIMEOUT),
		PCS_OPTION_CONNECTTIMEOUT, (void *)((long)CONNECTTIMEOUT),
		PCS_OPTION_END);
	return pcs;
}

void destroy_pcs(Pcs *pcs)
{
	pcs_destroy(pcs);
}

#pragma endregion

char *tail(char *filename)
{
    char *s;

    while (*filename) {
        s = strrchr(filename, '/');
        if (s == NULL)
            break;
        if (s[1])
            return (s + 1);
        *s = '\0';
    }
    return (filename);
}

static void prompt(shellContext *ctx)
{
    printf("%s:%s> ", "baidu@PCS", ctx->workDir);
    fflush(stdout);
}

static int cli_char_available(unsigned char *c)
{
    fd_set fdset;
    struct timeval tv;

    FD_ZERO(&fdset);
    FD_SET(0, &fdset);
    tv.tv_sec = 0;
    tv.tv_usec = 10000;
    if(select(1, &fdset, NULL, NULL, &tv) > 0) {
        *c = getchar();
        return 1;
    }
    return 0;
}

static void cursor_left(void)
{
    if (cmd_cursor > 0) {
        cmd_cursor--;
        putchar(ESC);
        putchar(0x5b);
        putchar(CURSOR_LEFT);
        fflush(stdout);
    }
}

static void cursor_right(void)
{
    if (cmd_cursor < cmd_len) {
        cmd_cursor++;
        putchar(ESC);
        putchar(0x5b);
        putchar(CURSOR_RIGHT);
        fflush(stdout);
    }
}

static void cursor_home(void)
{
    while (cmd_cursor > 0) {
        cursor_left();
    }
}

static void delete_to_eol(void)
{
    putchar(ESC);
    putchar(0x5b);
    putchar(CURSOR_END);
    fflush(stdout);
}

static void rewrite_to_eol(void)
{
    while (cmd_cursor < cmd_len) {
        putchar(cmd_buf[cmd_cursor++]);
    }
    fflush(stdout);
}

static void delete_line(void)
{
    cursor_home();
    delete_to_eol();
}

static void append_line(void)
{
    u32 cursor_save;

    cursor_save = cmd_cursor;
    rewrite_to_eol();
    while (cmd_cursor > cursor_save) {
        cursor_left();
    }
}

static void delete_char(int backspace)
{
    u32 j;

    if (cmd_len == 0 || 
            (backspace && cmd_cursor == 0) || 
            (!backspace && cmd_cursor == cmd_len))
        return;

    if (backspace)
        cursor_left();
    delete_to_eol();

    /* concatenate command string */
    cmd_len--;
    for (j = cmd_cursor; j < cmd_len; j++) {
        cmd_buf[j] = cmd_buf[j + 1];
    }

    /* rewrite command part to the right of cursor */
    append_line();
    cmd_buf[cmd_len+1] = 0;
//    printf ("<<%s>>\n", cmd_buf);
}

static void insert_char(char ch)
{
    u32 j;

    delete_to_eol();
    for (j = cmd_len; j > cmd_cursor; j--) {
        cmd_buf[j] = cmd_buf[j - 1];
    }
    cmd_len++;
    cmd_buf[cmd_cursor++] = ch;

    append_line();
}

static void cmd_history_put(void)
{
    memcpy(&cmd_history.buf[cmd_history.idx].cmd, &cmd_buf, cmd_len);
    cmd_history.buf[cmd_history.idx].cmd_len = cmd_len - 1; /* don't include CR */
    if (cmd_history.len < MAX_CMD_HISTORY_LEN) {
        cmd_history.len++;
    }
    if (++cmd_history.idx >= MAX_CMD_HISTORY_LEN) {
        cmd_history.idx = 0;
    }
    cmd_history.scroll = 0;
}

static void cmd_history_get(void)
{
    u32 idx;

    if (cmd_history.idx >= cmd_history.scroll) {
        idx = cmd_history.idx - cmd_history.scroll;
    }
    else {
        idx = MAX_CMD_HISTORY_LEN - (cmd_history.scroll - cmd_history.idx);
    }

    cmd_len = cmd_history.buf[idx].cmd_len;
    memcpy(&cmd_buf, &cmd_history.buf[idx].cmd, cmd_len);

}

static void get_old_cmd(void)
{
    delete_line();
    cmd_history_get();
    rewrite_to_eol();
}

static void process_escape_seq(char ch_1, char ch_2)
{
    if (ch_1 == 0x5b) {
        switch (ch_2) {
            case CURSOR_UP:
                if (cmd_history.scroll < cmd_history.len) {
                    cmd_history.scroll++;
                    get_old_cmd();
                }
                else {
                    putchar(BEL);
                    fflush(stdout);
                }
                break;

            case CURSOR_DOWN:
                if (cmd_history.scroll > 0) {
                    cmd_history.scroll--;

                    if (cmd_history.scroll > 0) {
                        get_old_cmd();
                    }
                    else {
                        delete_line();
                        cmd_len = 0;
                        cmd_cursor = 0;
                    }
                }
                else {
                    putchar(BEL);
                    fflush(stdout);
                }
                break;

            case CURSOR_RIGHT:
                cursor_right();
                break;

            case CURSOR_LEFT:
                cursor_left();
                break;

            case CURSOR_HOME:
                cursor_home();
                break;

            case CURSOR_END:
                while (cmd_cursor < cmd_len) {
                    cursor_right();
                }
                break;

            default:
                break;
        }
    }
}

static int empty_cmd_line(void)
{
    u32 j;

    for (j = 0; j < cmd_len; j++) {
        if ((cmd_buf[j] != ' ') && (cmd_buf[j] != CR)) {
            return 0;
        }
    }
    return 1;
}

static int cmd_auto_complete(void)
{
    cli_cmd_t *cli_cmd;
    u32 i, match;
        //printf ("<%s> \n", cmd_buf);
    for (i = 0; i < sizeof(cli_cmd_table)/sizeof(cli_cmd_t); i++) {
        cli_cmd = &cli_cmd_table[i];
        //      printf ("cli_cmd %s\n", cli_cmd->syntax);

        if (strlen(cli_cmd->syntax) > MAX_CMD_LEN) {
            /* Command too long */
            continue;
        }
        match = 0; 
        if (strstr(cli_cmd->syntax, cmd_buf) == cli_cmd->syntax) {
            /* Command word mismatch */
            match = 1;
            break;
        }
    }

    if (match) {
        memset(cmd_buf, 0, sizeof(cmd_buf));
        //      printf ("sizeof %d", sizeof(cmd_buf));
        strcpy(cmd_buf, cli_cmd->syntax);
        //      printf ("cmd_buf %s \t syntax %s \t cmd_len %d \t strlen %d\n", cmd_buf, cli_cmd->syntax, cmd_len, strlen(cli_cmd->syntax));
        for (i = cmd_cursor; i < strlen(cli_cmd->syntax); i++){
        //              printf ("ch %c \n", cmd_buf[i]);
            putchar(cmd_buf[i]);
        }
        fflush(stdout);
        cmd_len = strlen(cli_cmd->syntax);
        cmd_cursor = cmd_len;
    }
    return 1;
}

static void fill_buf(char ch)
{
    /*echo*/
    if (cmd_len < MAX_CMD_LEN) {
        putchar(ch);
        fflush(stdout);
    }

    if (ch != CR) {
        if (cmd_len < MAX_CMD_LEN) {
            if (cmd_cursor < cmd_len) {
                insert_char(ch);
            }
            else {
                cmd_buf[cmd_cursor++] = ch;
                if (cmd_len < cmd_cursor) {
                    cmd_len++;
                }
            }
        }
    }
}

static void cmd_readied(void)
{

    putchar(LF);
    fflush(stdout);

    /* Ensure that CR is present in buffer in case of buffer overflow */
    if (cmd_len == MAX_CMD_LEN) {
        cmd_buf[MAX_CMD_LEN - 1] = CR;
    }
    else {
        cmd_buf[cmd_len++] = CR;
    }
    if (!empty_cmd_line()) {
        cmd_history_put();
    }

    cmd_buf[cmd_len++] = '\0';

    fflush(stdout);
}


static int cmd_ready(void)
{
    u8 ch;
    int ret = 0;
    u32 loop_count;

    loop_count = 0;
    while (cli_char_available(&ch) && (loop_count++ < 20)) {
//        printf("ch = %d, LF %d, CR %d ESC %d\n", ch, LF, CR, ESC);
        if (ch == LF) ch = CR;
        switch (ch) {
            case BS:
            case DEL:
                delete_char(1);
                break;
            case ESC:
                ch = getc(stdin);
                process_escape_seq(ch, getc(stdin));
                break;
            case HT:
                cmd_auto_complete();
                break;
            case CR:
                ret = 1;
                cmd_readied();
                break;
            default:
                fill_buf(ch);
        }
    }
    return ret;
}

static void cmd_get(char *buf)
{
    int i;
    cmd_len = 0;
    cmd_cursor = 0;

    strcpy(buf, cmd_buf);
    /* Remove CR */
    i = strlen(buf);
    if (i)
        buf[i-1] = '\0';
    /*clear for auto completion*/
    memset(cmd_buf, 0, sizeof(cmd_buf));
}

static void cli_cmd_help(void) 
{
    printf("Type '<group> ?' to get list of group commands, e.g. 'system ?'.\n");
    printf("Type '<command> ?' to get help on a command, e.g. 'system reboot ?'.\n");
    printf("Commands may be abbreviated, e.g. 'sy re' instead of 'system reboot'.\n");
}

/* Parse command */
static int cli_command(cli_cmd_id_t id, struct args *arg, shellContext *ctx)
{
    int status = -1;
        printf("--------> enter into cli command\n");
    if (!is_logged_on_experience() && id != CLI_CMD_ID_LOGIN && id != CLI_CMD_ID_QUIT) {
        printf("--------> \n");
    //    return 0;
    }
    switch (id) {
        case CLI_CMD_ID_HELP:
            status = cmd_help(ctx, arg);
            break;
        case CLI_CMD_ID_LS:
            status = cmd_ls(ctx, arg);
            break;
        case CLI_CMD_ID_CD:
            status = cmd_cd(ctx, arg);
            break;
        case CLI_CMD_ID_CP:
            status = cmd_copy(ctx, arg);
            break;
        case CLI_CMD_ID_MV:
            status = cmd_move(ctx, arg);
            break;
        case CLI_CMD_ID_RM:
            status = cmd_remove(ctx, arg);
            break;
        case CLI_CMD_ID_CAT:
            status = cmd_cat(ctx, arg);
            break;
        case CLI_CMD_ID_PWD:
            status = cmd_pwd(ctx, arg);
            break;
        case CLI_CMD_ID_SET:
            status = cmd_set(ctx, arg);
            break;
        case CLI_CMD_ID_ECHO:
            status = cmd_echo(ctx, arg);
            break;
        case CLI_CMD_ID_MKDIR:
            status = cmd_mkdir(ctx, arg);
            break;
        case CLI_CMD_ID_COMPARE:
            status = cmd_compare(ctx, arg);
            break;
        case CLI_CMD_ID_CONTEXT:
            status = cmd_context(ctx, arg);
            break;
        case CLI_CMD_ID_DOWNLOAD:
            status = cmd_download(ctx, arg);
            break;
        case CLI_CMD_ID_ENCODE:
            status = cmd_encode(ctx, arg);
            break;
        case CLI_CMD_ID_FIX:
            status = cmd_fix(ctx, arg);
            break;
        case CLI_CMD_ID_LOGIN:
            status = cmd_login(ctx, arg);
            break;
        case CLI_CMD_ID_LOGOUT:
            status = cmd_logout(ctx, arg);
            break;
        case CLI_CMD_ID_META:
            status = cmd_meta(ctx, arg);
            break;
        case CLI_CMD_ID_QUOTA:
            status = cmd_quota(ctx, arg);
            break;
        case CLI_CMD_ID_SEARCH:
            status = cmd_search(ctx, arg);
            break;
        case CLI_CMD_ID_SYNC:
            status = cmd_sync(ctx, arg);
            break;
        case CLI_CMD_ID_UPLOAD:
            status = cmd_upload(ctx, arg);
            break;
        case CLI_CMD_ID_VERSION:
            status = cmd_version(ctx, arg);
            break;
        case CLI_CMD_ID_WHO:
            status = cmd_who(ctx, arg);
            break;
        case CLI_CMD_ID_QUIT:
            status = cmd_quit(ctx, arg);
            break;
        default:
            printf("command id: %d not implemented\n", id);
            break;
    }

    return status;
}


static char *cli_lower_word(char *in, char *out)
{
    int i, len;

    len = strlen(in);
    for (i = 0; i <= len; i++)
        out[i] = tolower(in[i]);
    return out;
}

static void cli_build_words(char *str, int *count, char **words, u8 lower)
{
    int  i, j, len;
    char *p;

    len = strlen(str);
    j = 0;
    *count = 0;
    for (i = 0; i < len; i++) {
        p = &str[i];
        if (isspace(*p)) {
            j = 0;
            *p = '\0';
        } else {
            if (j == 0) {
                words[*count] = p;
                (*count)++;
            }
            if (lower)
                *p = tolower(*p);
            j++;
        }
    }
}

/* Header with optional new line before and after */
static void cli_header_nl_char(const char *txt, u8 pre, u8 post, char c)
{
    int i, len;

    if (pre)
        printf("\n");
    printf("%s:\n", txt);
    len = (strlen(txt) + 1);
    for (i = 0; i < len; i++)
        printf("%c", c);
    printf("\n");
    if (post)
        printf("\n");
}


static void cli_header_nl(const char *txt, u8 pre, u8 post)
{
    cli_header_nl_char(txt, pre, post, '-');
}

static void parse_command(shellContext *ctx)
{
    char *cmd, *stx, *cmd2;
    char cmd_buf[MAX_CMD_LEN], stx_buf[MAX_CMD_LEN], *cmd_words[64], *stx_words[64];
    char cmd1_buf[MAX_WORD_LEN], cmd2_buf[MAX_WORD_LEN];
    int i, i_cmd, i_stx, i_parm = 0, cmd_count, stx_count, max, len, j, error, idx;
    int match_cmds[sizeof(cli_cmd_table)/sizeof(cli_cmd_t)], match_count = 0;
    cli_cmd_t *cli_cmd;
    u8 match, help = 0;
    struct args arg = {0};

    /* Read command and skip leading spaces */
    cmd_get(cmd_buf);

    /* Build array of command words */
    cli_build_words(cmd_buf, &cmd_count, cmd_words, 0);

    /* Remove trailing 'help' or '?' command */
    if (cmd_count > 1) {
        cmd = cli_lower_word(cmd_words[cmd_count-1], cmd1_buf);
        if (strcmp(cmd, "?") == 0 || strcmp(cmd, "help") == 0) {
            cmd_count--;
            help = 1;
        }
    }

    /* Compare entered command with each entry in CLI command table */
    for (i = 0; i < sizeof(cli_cmd_table)/sizeof(cli_cmd_t); i++) {
        cli_cmd = &cli_cmd_table[i];

        if (strlen(cli_cmd->syntax) > MAX_CMD_LEN) {
            /* Command too long */
            continue;
        }

        /* Build array of syntax words */
        strcpy(stx_buf, cli_cmd->syntax);
        cli_build_words(stx_buf, &stx_count, stx_words, 1);

        match = 1; 
        for (i_cmd = 0, i_stx = 0; i_stx < stx_count; i_cmd++, i_stx++) {
            stx = stx_words[i_stx];

            if (i_cmd >= cmd_count)
                continue;

            cmd = cli_lower_word(cmd_words[i_cmd], cmd1_buf);
            if (strstr(stx, cmd) != stx) {
                /* Command word mismatch */
                match = 0;
                break;
            }
        }

        if (match) {
            match_cmds[match_count++] = i;
        }
    }

    if (match_count == 0) {
        /* No matching commands */
        printf("Invalid command\n");
    }
    else if (match_count == 1) {
#if 0
        /* One matching command */
        cli_cmd = &cli_cmd_table[match_cmds[0]];

        /* Rebuild array of syntax words */
        strcpy(stx_buf, cli_cmd->syntax);
        cli_build_words(stx_buf, &stx_count, stx_words, 1);

        if (help) {
            u8 done[sizeof(cli_parm_table)/sizeof(*parm)];

            memset(done, 0, sizeof(done));
            cli_header_nl("Description", 0, 0);
            printf("%s.\n\n", cli_cmd->descr);
            cli_header_nl("Syntax", 0, 0);
            printf("%s\n\n", cli_cmd->syntax);
            for (max = 0, i = 0; i_parm && i < 2; i++) {
                for (i_stx = i_parm; i_stx < stx_count; i_stx++) {
                    if ((parm = cli_parm_lookup(stx_words[i_stx], cli_cmd->id, &idx)) == NULL)
                        continue;
                    len = strlen(parm->txt);
                    if (i == 0) {
                        if (!(parm->flags & CLI_PARM_FLAG_NO_TXT)) {
                            if (len > max)
                                max = len;
                        }
                    }
                    else if (!done[idx]) {
                        done[idx] = 1;
                        if (i_stx == i_parm)
                            cli_header_nl("Parameters", 0, 0);
                        if (!(parm->flags & CLI_PARM_FLAG_NO_TXT)) {
                            printf("%s", parm->txt);
                            for (j = len; j < max; j++)
                                printf(" ");
                            printf(": ");
                        }
                        printf("%s\n", parm->help);
                    }
                }
            }
        }
        else {
            enum {
                CLI_STATE_IDLE,
                CLI_STATE_PARSING,
                CLI_STATE_DONE,
                CLI_STATE_ERROR
            } state;
            u8 end = 0, separator, skip_parm;

            /* Create default parameters */
            req = &cli_req;

            /* Parse arguments */
            state = CLI_STATE_IDLE;
            for (i_cmd = i_parm, i_stx = i_parm; i_parm && i_stx < stx_count; i_stx++) {
                stx = stx_words[i_stx];

                separator = (strcmp(stx, "|") == 0);
                skip_parm = 0;
                switch (state) {
                    case CLI_STATE_IDLE:
                        if (stx[0] == '(' || stx[1] == '(') {
                            i = i_cmd;
                            state = CLI_STATE_PARSING;
                        }
                        break;
                    case CLI_STATE_PARSING:
                        break;
                    case CLI_STATE_ERROR:
                        if (end && separator) {
                            /* Parse next group */
                            i_cmd = i;
                            state = CLI_STATE_PARSING;
                        } else if (strstr(stx, ")]") != NULL) {
                            i_cmd = i;
                            state = CLI_STATE_IDLE;
                        }
                        skip_parm = 1;
                        break;
                    case CLI_STATE_DONE:
                        if (end && !separator)
                            state = CLI_STATE_IDLE;
                        else
                            skip_parm = 1;
                        break;
                    default:
                        printf("Illegal state: %d\n", state);
                        return;
                }
                end = (strstr(stx, ")") != NULL);

#if 0
                printf("stx: %s, cmd: %s, state: %s->%s\n",
                        stx, i_cmd < cmd_count ? cmd_words[i_cmd] : NULL,
                        state == CLI_STATE_IDLE ? "IDLE" :
                        state == CLI_STATE_PARSING ? "PARSING" :
                        state == CLI_STATE_ERROR ? "ERROR" : "DONE");
#endif
                /* Skip if separator or not in parsing state */
                if (separator || skip_parm)
                    continue;

                /* Lookup parameter */
                if ((parm = cli_parm_lookup(stx, cli_cmd->id, &idx)) == NULL) {
                    printf("Unknown parameter: %s\n", stx);
                    return;
                } 

                if (i_cmd >= cmd_count) {
                    /* No more command words */
                    cmd = NULL;
                    error = 1;
                }
                else {
                    /* Parse command parameter */
                    do {
                        cmd = cli_lower_word(cmd_words[i_cmd], cmd1_buf);
                        cmd2 = ((i_cmd + 1) < cmd_count ? 
                                cli_lower_word(cmd_words[i_cmd + 1], cmd2_buf) : NULL);
                        error = cli_parse_parm(parm->type, cli_cmd, cmd, cmd2, 
                                stx, cmd_words[i_cmd], req); 
#if 0
                        printf("stx: %s, cmd: %s, error: %d\n", stx, cmd, error);
#endif
                        if (error)
                            break;
                        if (parm->flags & CLI_PARM_FLAG_SET)
                            req->set = 1;
                        i_cmd += req->parm_parsed;
                    } while (i_cmd < cmd_count && (parm->flags & CLI_PARM_FLAG_DUAL));
                }

                /* No error or error in optional parameter */
                if (!error ||
                        (stx[0] == '[' && (stx[1] != '(' || stx[2] == '['))) {
                    if (state == CLI_STATE_PARSING && end)
                        state = CLI_STATE_DONE;
                    continue;
                }

                /* Error in mandatory parameter of group */
                if (state == CLI_STATE_PARSING) {
                    state = CLI_STATE_ERROR;
                    continue;
                }

                /* Error in mandatory parameter */
                if (cmd == NULL)
                    printf("Missing %s parameter\n\n", parm->txt);
                else
                    printf("Invalid %s parameter: %s\n\n", parm->txt, cmd);
                printf("Syntax:\n%s\n", cli_cmd->syntax);
                return;
            } /* for loop */
            if (i_parm) { 
                if (i_cmd < cmd_count) {
                    printf("Invalid parameter: %s\n\n", cmd_words[i_cmd]);
                    printf("Syntax:\n%s\n", cli_cmd->syntax);
                    return;
                }
                if (state == CLI_STATE_ERROR) {
                    printf("Invalid parameter\n\n");
                    printf("Syntax:\n%s\n", cli_cmd->syntax);
                    return;
                }
            } /* Parameter handling */
#endif
        if (!parse_cmds(&arg, cmd_count, cmd_words, u8_is_utf8_sys() ? NULL : mbs2utf8)) {
            int status;

            /* Handle CLI command */
            cli_cmd = &cli_cmd_table[match_cmds[0]];

            for (i = 0; i < cmd_count; i++) {
                printf("cmdid %d, syntax %s\n", cli_cmd->id, cmd_words[i]);
                //printf("cmdid %d, syntax %s\n", cli_cmd->id, arg.argv[i]);
            }
            status = cli_command(cli_cmd->id, &arg, ctx);
            printf("cmd exec done, status %d\n", status);
        }
    }
} /* cli_parse_command */



struct cli_cmd_t *getcmd(char *name)
{
    const char *p;
    char *q;
    struct cli_cmd_t *cmd, *found;
    int nmatches, longest;

    longest = 0;
    nmatches = 0;
    found = 0;
    for (cmd = cli_cmd_table; (p = cmd->syntax) != NULL; cmd++) {
        for (q = name; *q == *p++; q++)
            if (*q == 0)        /* exact match? */
                return (cmd);
        if (!*q) {              /* the name was a prefix */
            if (q - name > longest) {
                longest = q - name;
                nmatches = 1;
                found = cmd;
            } else if (q - name == longest)
                nmatches++;
        }
    }
    if (nmatches > 1)
        return ((struct cli_cmd_t *)-1);
    return (found);
}

/*
 *  * Slice a string up into argc/argv.
 *   */
static void makeargv(void)
{
    char *cp;
    char **argp = margv;

    margc = 0;
    for (cp = line; *cp;) {
        while (isspace(*cp))
            cp++;
        if (*cp == '\0')
            break;
        *argp++ = cp;
        margc += 1;
        while (*cp != '\0' && !isspace(*cp))
            cp++;
        if (*cp == '\0')
            break;
        *cp++ = '\0';
    }
    *argp++ = 0;
}

void quit(int argc, char *argv[])
{
    (void)argc;
    (void)argv;                 /* Quiet unused warning */
    exit(0);
}

void display_banner(void)
{
    /*Display banner*/
    printf("__________        .__________          ___________________   _________\n");
    printf("\\______   \\_____  |__\\______ \\  __ __  \\______   \\_   ___ \\ /   _____/\n");
    printf(" |    |  _/\\__  \\ |  ||    |  \\|  |  \\  |     ___/    \\  \\/ \\_____  \\ \n");
    printf(" |    |   \\ / __ \\|  ||    `   \\  |  /  |    |   \\     \\____/        \\\n");
    printf(" |______  /(____  /__/_______  /____/   |____|    \\______  /_______  /\n");
    printf("        \\/      \\/           \\/                          \\/        \\/ \n");
}

static void restore_keypress(void)
{
    tcsetattr(0, TCSANOW, &stored_settings);
}


static void interactive_command(shellContext *ctx)
{

    struct termios current_cfg;

    tcgetattr(0, &stored_settings);

    current_cfg = stored_settings;

    /* Disable canonical mode, and set buffer size to 1 byte */
    current_cfg.c_lflag &= (~ICANON);
    current_cfg.c_lflag &= (~ECHO);
    current_cfg.c_cc[VTIME] = 0;
    current_cfg.c_cc[VMIN] = 1;

    tcsetattr(0,TCSANOW, &current_cfg);

    atexit(restore_keypress);


    cmd_history.len = 0;
    cmd_history.idx = 0;
    cmd_history.scroll = 0;

    display_banner();
    do {
        if (cmd_ready()) {
            parse_command(ctx);
            if (suspended)
                prompt(ctx);
        }
    } while (suspended);
}

int main(int argc, char *argv[])
{
    struct cli_cmd_t *cmd;
    struct args arg = {0};
    shellContext context = {0};
    int rc = 0;
    char *errmsg = NULL, *val = NULL;

    signal(SIGINT, SIG_IGN);
    setlocale(LC_ALL, "");
    program = filename(argv[0]);

    hook_cjson();
    init_context(&context, &arg);


    if (parse_args(&arg, argc, argv, u8_is_utf8_sys() ? NULL : mbs2utf8)) {
        usage();
        free_args(&arg);
        return -1;
    }
    if (has_optEx(&arg, "context", &val)) {
        if (restore_context(&context, val)) {
            rc = -1;
            goto out2;
        }
        remove_opt(&arg, "context", NULL);
    }
    else {
        restore_context(&context, NULL);
    }
    if (errmsg) {
        printf("%s\n", errmsg);
        pcs_free(errmsg);
    }
    context.pcs = create_pcs(&context);
    if (!context.pcs) {
        rc = -1;
        printf("Can't create pcs context.\n");
        goto out2;
    }
    if (argc == 1) {
        /* interactive shell */
        interactive_command(&context);
        printf("----------> quit from interactive shell!\n");
        goto out1;
    }
    printf("CMD %s %d\n", arg.name, argc);
    if (!arg.cmd) {
        usage();
        goto out2;
    }
    printf("CMD %s %s\n", arg.cmd, arg.name);
    cmd = getcmd(arg.cmd);
    printf("ID %d\n", cmd->id);
    rc = cli_command(cmd->id, &arg, &context);

out1:
    printf("----------> EXIT 1!\n");
    destroy_pcs(context.pcs);
    save_context(&context);
out2:
    printf("----------> EXIT 2!\n");
    free_context(&context);
    free_args(&arg);
    pcs_print_leak();
    return rc;
}

