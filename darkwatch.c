/*
 * DARKWATCH - Real-Time SSH Attack Detection & Monitoring System (single-file edition)
 * Terminal-based IDS-style monitor for Windows OpenSSH telemetry (also runs on Linux with -f <logfile>).
 *
 * Pipeline: collect -> parse -> track -> correlate -> detect -> score -> alert -> display
 *
 * Build (Windows, MinGW):  gcc -std=c11 -O2 -o darkwatch.exe darkwatch.c -lws2_32
 * Build (Windows, MSVC):   cl /O2 darkwatch.c ws2_32.lib
 * Build (Linux/macOS):     gcc -std=c11 -O2 -o darkwatch darkwatch.c
 * Run:  darkwatch.exe          (as Administrator, reads the OpenSSH event log live)
 *       darkwatch.exe -h       (all options)
 *
 * Sections:  1 types  2 platform  3 parser  4 collector  5 engine  6 logger  7 terminal UI  8 main
 */
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <conio.h>
#else
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif


/* ====================================================================
 * 1. TYPES, CONSTANTS AND PROTOTYPES
 * ==================================================================== */
/* DARKWATCH - real-time SSH attack detection & monitoring (shared definitions) */

#define DW_VERSION "1.0"
#define RST  "\033[0m"
#define BOLD "\033[1m"
#define DIM  "\033[2m"
#define GRN  "\033[92m"
#define CYN  "\033[96m"
#define YEL  "\033[93m"
#define MAG  "\033[95m"
#define RED  "\033[91m"
#define CRITC "\033[1;97;41m"

enum { EV_NONE, EV_CONN, EV_FAIL, EV_OK, EV_INVALID, EV_DISC, EV_ALERT };
enum { LV_LOW, LV_SUSP, LV_MED, LV_HIGH, LV_CRIT };

#define RING 64
#define MAXU 16
#define MAXSRC 4096

typedef struct { time_t ts; int type; char ip[46]; char user[64]; char msg[400]; } SecurityEvent;

typedef struct {
    int fail_thresh, window, conn_thresh, conn_window, enum_thresh, port;
    char allow[16][46]; int nallow;
} Config;

typedef struct {
    char ip[46]; int used;
    int failed_logins, successful_logins, connection_count, unique_usernames, threat_score;
    time_t first_seen, last_seen, last_fail;
    time_t fail_ring[RING], conn_ring[RING]; int fail_n, conn_n;
    char users[MAXU][64];
    int fail_then_success, enum_alerted;
    time_t last_brute_alert, last_burst_alert;
    int recent_fails, burst, pts_fail, pts_users, pts_burst, pts_seq, pts_hist, pts_alert;
} Attacker;

typedef struct { time_t ts; int level; char ip[46]; char rule[40]; char mitre[16]; char msg[200]; } Alert;
typedef struct { long events, conns, fails, succ, alerts; int sources; } Stats;

/* collector: where telemetry comes from */
typedef void (*LineCb)(const char *line, time_t ts, void *ud);
typedef struct {
    int use_eventlog, from_start, rate, eof_hit;
    char path[260]; FILE *fp;
    unsigned long long last_id;
    void *buf; unsigned long bufsz;
    char err[512];
} Collector;
int  collector_init(Collector *c);                       /* 0 ok, -1 error (see c->err) */
int  collector_poll(Collector *c, LineCb cb, void *ud);  /* lines delivered, -1 fatal */
void collector_close(Collector *c);

/* parser */
time_t parse_ts(const char *line);
int    parse_line(const char *line, time_t ts, SecurityEvent *e);

/* engine: tracker + correlation + detection + scoring + alerts */
void  engine_init(const Config *c);
void  engine_ingest(const SecurityEvent *e);
void  engine_tick(void);
time_t engine_now(void);
const Config *engine_cfg(void);
const Stats  *engine_stats(void);
int   engine_sources_sorted(Attacker **out, int max);
int   engine_alert_count(void);
const Alert *engine_alert_recent(int i);                 /* 0 = newest */
int   engine_feed_count(void);
const SecurityEvent *engine_feed_recent(int i);          /* 0 = newest */
int   engine_feed_total(void);
const SecurityEvent *engine_feed_abs(int idx);
int   engine_global_score(void);
const char *level_name(int lv);
int   level_for_score(int s);

/* logger */
void log_init(void);
void log_event(const SecurityEvent *e);
void log_alert(const Alert *a);
int  log_export_report(const char *path);

/* terminal UI */
void ui_draw(int view, int ssh_online, const char *source, int paused);
void ui_fmt_event(char *out, size_t sz, const SecurityEvent *e, int color);

/* platform */
void plat_init(int ui);
void plat_shutdown(void);
void plat_sleep_ms(int ms);
int  plat_key(void);
int  plat_port_open(int port);

/* ====================================================================
 * 2. PLATFORM LAYER (console, keyboard, sleep, port check)
 * ==================================================================== */
#ifdef _WIN32
typedef SOCKET sock_t;
typedef int dw_socklen;
#define CLOSESOCK closesocket
#else
typedef int sock_t;
typedef socklen_t dw_socklen;
#define CLOSESOCK close
static struct termios saved_tio; static int tio_saved = 0;
#endif
static int ui_mode = 0;

void plat_init(int ui) {
    ui_mode = ui;
#ifdef _WIN32
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE); DWORD m = 0;
    if (GetConsoleMode(h, &m)) SetConsoleMode(h, m | 0x0004 /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */);
#else
    if (ui && tcgetattr(0, &saved_tio) == 0) {
        struct termios t = saved_tio; t.c_lflag &= ~(tcflag_t)(ICANON | ECHO); t.c_cc[VMIN] = 0; t.c_cc[VTIME] = 0;
        tcsetattr(0, TCSANOW, &t); tio_saved = 1;
    }
#endif
    if (ui) { printf("\033[?1049h\033[?25l\033[2J"); fflush(stdout); }
}
void plat_shutdown(void) {
    if (ui_mode) { printf("\033[?25h\033[?1049l"); fflush(stdout); }
#ifdef _WIN32
    WSACleanup();
#else
    if (tio_saved) tcsetattr(0, TCSANOW, &saved_tio);
#endif
}
void plat_sleep_ms(int ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec d = {ms / 1000, (long)(ms % 1000) * 1000000L}; nanosleep(&d, NULL);
#endif
}
int plat_key(void) {
#ifdef _WIN32
    return _kbhit() ? _getch() : -1;
#else
    unsigned char c; return (tio_saved && read(0, &c, 1) == 1) ? c : -1;
#endif
}
/* Is something accepting TCP connections on localhost:port? (real SSH service status) */
int plat_port_open(int port) {
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (s == INVALID_SOCKET) return 0;
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
#else
    if (s < 0) return 0;
    fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
#endif
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port); a.sin_addr.s_addr = htonl(0x7f000001UL);
    int ok = 0;
    if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) ok = 1;
    else {
        fd_set w; FD_ZERO(&w); FD_SET(s, &w);
        struct timeval tv = {0, 300000};
        if (select((int)s + 1, NULL, &w, NULL, &tv) > 0) {
            int err = 1; dw_socklen l = sizeof err;
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &l);
            ok = (err == 0);
        }
    }
    CLOSESOCK(s);
    return ok;
}

/* ====================================================================
 * 3. PARSER (raw text -> SecurityEvent)
 * ==================================================================== */
time_t parse_ts(const char *line) {
    struct tm tm; memset(&tm, 0, sizeof tm); tm.tm_isdst = -1;
    int y, mo, d, h, mi, s;
    if (sscanf(line, "%4d-%2d-%2d%*1[T ]%2d:%2d:%2d", &y, &mo, &d, &h, &mi, &s) == 6 && y > 1990) {
        tm.tm_year = y - 1900; tm.tm_mon = mo - 1; tm.tm_mday = d; tm.tm_hour = h; tm.tm_min = mi; tm.tm_sec = s;
        return mktime(&tm);
    }
    static const char *mon[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    char m[4];
    if (sscanf(line, "%3s %2d %2d:%2d:%2d", m, &d, &h, &mi, &s) == 5) {
        for (int i = 0; i < 12; i++) if (!strcmp(m, mon[i])) {
            time_t now = time(NULL); struct tm *cur = localtime(&now);
            tm.tm_year = cur->tm_year; tm.tm_mon = i; tm.tm_mday = d; tm.tm_hour = h; tm.tm_min = mi; tm.tm_sec = s;
            time_t t = mktime(&tm);
            if (t > now + 2 * 86400) { tm.tm_year--; t = mktime(&tm); }
            return t;
        }
    }
    return 0;
}

static void clean(char *s) {   /* usernames are attacker-controlled: strip control chars (terminal-escape injection) */
    for (; *s; s++) if ((unsigned char)*s < 32 || (unsigned char)*s > 126) *s = '?';
}
static void tok(char *dst, size_t sz, const char *p, int ipchars) {
    size_t n = 0;
    while (*p && n + 1 < sz) {
        if (ipchars ? !(isxdigit((unsigned char)*p) || *p == ':' || *p == '.') : (*p == ' ' || *p == '\r' || *p == '\n')) break;
        dst[n++] = *p++;
    }
    dst[n] = 0;
}

int parse_line(const char *line, time_t ts, SecurityEvent *e) {
    memset(e, 0, sizeof *e);
    e->ts = ts ? ts : time(NULL);
    const char *p;
    if ((p = strstr(line, "Failed password for ")) || (p = strstr(line, "Failed publickey for ")) ||
        (p = strstr(line, "Failed keyboard-interactive")) ) {
        e->type = EV_FAIL; p = strstr(p, " for "); if (!p) return 0; p += 5;
    } else if ((p = strstr(line, "Accepted "))) {
        e->type = EV_OK; p = strstr(p, " for "); if (!p) return 0; p += 5;
    } else if ((p = strstr(line, "Invalid user "))) {
        e->type = EV_INVALID; p += 13;
    } else if ((p = strstr(line, "Connection from "))) {
        e->type = EV_CONN; tok(e->ip, sizeof e->ip, p + 16, 1); return e->ip[0] != 0;
    } else if (strstr(line, "Connection closed by ") || strstr(line, "Disconnected from ") || strstr(line, "Received disconnect from ")) {
        const char *pp = strstr(line, " port ");
        if (!pp) return 0;
        const char *st = pp; while (st > line && st[-1] != ' ') st--;
        char tmp[46]; size_t n = (size_t)(pp - st); if (n == 0 || n >= sizeof tmp) return 0;
        memcpy(tmp, st, n); tmp[n] = 0; tok(e->ip, sizeof e->ip, tmp, 1);
        e->type = EV_DISC; return e->ip[0] != 0 && strlen(e->ip) == n;
    } else return 0;
    if (!strncmp(p, "invalid user ", 13)) p += 13;
    tok(e->user, sizeof e->user, p, 0);
    const char *q = strstr(p, " from ");
    if (!q) return 0;
    tok(e->ip, sizeof e->ip, q + 6, 1);
    clean(e->user);
    return e->ip[0] != 0;
}

/* ====================================================================
 * 4. COLLECTOR (Windows Event Log or file tail)
 * ==================================================================== */
/* Collector: Windows Event Log (OpenSSH/Operational) or a tailed log file. */
#ifdef _WIN32
#endif

#ifdef _WIN32
/* --- Windows Event Log API, loaded at runtime from wevtapi.dll (no winevt.h / import library needed) --- */
typedef HANDLE DW_EVT;
#define DW_QRY_CHANNEL 0x1
#define DW_QRY_FORWARD 0x100
#define DW_QRY_REVERSE 0x200
#define DW_RENDER_XML  1
#ifndef ERROR_ACCESS_DENIED
#define ERROR_ACCESS_DENIED 5L
#endif
#ifndef ERROR_INSUFFICIENT_BUFFER
#define ERROR_INSUFFICIENT_BUFFER 122L
#endif
#ifndef ERROR_EVT_CHANNEL_NOT_FOUND
#define ERROR_EVT_CHANNEL_NOT_FOUND 15007L
#endif
typedef DW_EVT (WINAPI *EvtQuery_fn)(DW_EVT, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL   (WINAPI *EvtNext_fn)(DW_EVT, DWORD, DW_EVT *, DWORD, DWORD, PDWORD);
typedef BOOL   (WINAPI *EvtRender_fn)(DW_EVT, DW_EVT, DWORD, DWORD, PVOID, PDWORD, PDWORD);
typedef BOOL   (WINAPI *EvtClose_fn)(DW_EVT);
static EvtQuery_fn pEvtQuery; static EvtNext_fn pEvtNext; static EvtRender_fn pEvtRender; static EvtClose_fn pEvtClose;
static HMODULE g_wevt;
static int load_wevt(Collector *c) {
    if (g_wevt) return 1;
    g_wevt = LoadLibraryA("wevtapi.dll");
    if (g_wevt) {
        pEvtQuery  = (EvtQuery_fn)(void *)GetProcAddress(g_wevt, "EvtQuery");
        pEvtNext   = (EvtNext_fn)(void *)GetProcAddress(g_wevt, "EvtNext");
        pEvtRender = (EvtRender_fn)(void *)GetProcAddress(g_wevt, "EvtRender");
        pEvtClose  = (EvtClose_fn)(void *)GetProcAddress(g_wevt, "EvtClose");
    }
    if (!g_wevt || !pEvtQuery || !pEvtNext || !pEvtRender || !pEvtClose) {
        snprintf(c->err, sizeof c->err, "Cannot load wevtapi.dll (needs Windows Vista or newer). Use -f <logfile> instead.");
        return 0;
    }
    return 1;
}
static time_t dw_timegm(const struct tm *t) {      /* UTC struct tm -> time_t, no _mkgmtime needed */
    long y = t->tm_year + 1900, m = t->tm_mon + 1, d = t->tm_mday;
    y -= m <= 2;
    long era = (y >= 0 ? y : y - 399) / 400, yoe = y - era * 400;
    long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1, doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long long days = (long long)era * 146097 + doe - 719468;
    return (time_t)(days * 86400 + t->tm_hour * 3600L + t->tm_min * 60L + t->tm_sec);
}
static unsigned long long xml_id(const char *x) { const char *p = strstr(x, "<EventRecordID>"); return p ? strtoull(p + 15, NULL, 10) : 0; }
static time_t xml_time(const char *x) {
    const char *p = strstr(x, "SystemTime="); int y, mo, d, h, mi, s;
    if (!p || sscanf(p + 12, "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi, &s) != 6) return 0;
    struct tm tm; memset(&tm, 0, sizeof tm);
    tm.tm_year = y - 1900; tm.tm_mon = mo - 1; tm.tm_mday = d; tm.tm_hour = h; tm.tm_min = mi; tm.tm_sec = s;
    return dw_timegm(&tm);
}
static void xml_data(const char *x, char *out, size_t sz) {   /* concatenate every <Data>..</Data> */
    size_t n = 0; const char *p = x; out[0] = 0;
    while ((p = strstr(p, "<Data")) != NULL) {
        const char *gt = strchr(p, '>'); if (!gt) break;
        if (gt[-1] == '/') { p = gt; continue; }
        const char *end = strstr(gt + 1, "</Data>"); if (!end) break;
        if (n && n + 1 < sz) out[n++] = ' ';
        for (const char *c = gt + 1; c < end && n + 1 < sz; ) {
            if (!strncmp(c, "&amp;", 5)) { out[n++] = '&'; c += 5; }
            else if (!strncmp(c, "&lt;", 4)) { out[n++] = '<'; c += 4; }
            else if (!strncmp(c, "&gt;", 4)) { out[n++] = '>'; c += 4; }
            else if (!strncmp(c, "&quot;", 6)) { out[n++] = '"'; c += 6; }
            else if (!strncmp(c, "&apos;", 6)) { out[n++] = '\''; c += 6; }
            else out[n++] = *c++;
        }
        p = end;
    }
    out[n] = 0;
}
static int render(Collector *c, DW_EVT h, char *u8, size_t sz) {
    DWORD used = 0, props = 0;
    if (!c->buf) { c->bufsz = 65536; c->buf = malloc(c->bufsz); if (!c->buf) return 0; }
    if (!pEvtRender(NULL, h, DW_RENDER_XML, c->bufsz, c->buf, &used, &props)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return 0;
        void *nb = realloc(c->buf, used); if (!nb) return 0;
        c->buf = nb; c->bufsz = used;
        if (!pEvtRender(NULL, h, DW_RENDER_XML, c->bufsz, c->buf, &used, &props)) return 0;
    }
    return WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)c->buf, -1, u8, (int)sz, NULL, NULL) > 0;
}
static void err_text(Collector *c, DWORD e) {
    if (e == ERROR_EVT_CHANNEL_NOT_FOUND)
        snprintf(c->err, sizeof c->err, "Event log 'OpenSSH/Operational' not found. Install/start the OpenSSH Server (see README) or use -f <logfile>.");
    else if (e == ERROR_ACCESS_DENIED)
        snprintf(c->err, sizeof c->err, "Access denied reading the OpenSSH event log. Run this terminal as Administrator.");
    else snprintf(c->err, sizeof c->err, "Event log query failed (Windows error %lu).", (unsigned long)e);
}
static int evlog_init(Collector *c) {
    c->last_id = 0;
    if (!load_wevt(c)) return -1;
    DW_EVT q = pEvtQuery(NULL, L"OpenSSH/Operational", L"*", DW_QRY_CHANNEL | DW_QRY_REVERSE);
    if (!q) { err_text(c, GetLastError()); return -1; }
    if (!c->from_start) {                       /* live mode: skip history, start after newest record */
        DW_EVT ev; DWORD ret = 0; static char u8[131072];
        if (pEvtNext(q, 1, &ev, 1000, 0, &ret) && ret == 1) { if (render(c, ev, u8, sizeof u8)) c->last_id = xml_id(u8); pEvtClose(ev); }
    }
    pEvtClose(q);
    return 0;
}
static int evlog_poll(Collector *c, LineCb cb, void *ud) {
    wchar_t xp[128]; static char u8[131072], msg[4096]; int n = 0;
    _snwprintf(xp, 128, L"*[System[EventRecordID>%I64u]]", c->last_id);
    DW_EVT q = pEvtQuery(NULL, L"OpenSSH/Operational", xp, DW_QRY_CHANNEL | DW_QRY_FORWARD);
    if (!q) { DWORD e = GetLastError(); err_text(c, e); return (e == ERROR_EVT_CHANNEL_NOT_FOUND || e == ERROR_ACCESS_DENIED) ? -1 : 0; }
    DW_EVT ev[32]; DWORD ret = 0;
    while (pEvtNext(q, 32, ev, 200, 0, &ret)) {
        for (DWORD i = 0; i < ret; i++) {
            if (render(c, ev[i], u8, sizeof u8)) {
                unsigned long long id = xml_id(u8); if (id > c->last_id) c->last_id = id;
                xml_data(u8, msg, sizeof msg);
                cb(msg, xml_time(u8), ud); n++;
            }
            pEvtClose(ev[i]);
        }
    }
    pEvtClose(q);
    return n;
}
#endif

int collector_init(Collector *c) {
    c->eof_hit = 0; c->fp = NULL; c->buf = NULL; c->bufsz = 0; c->err[0] = 0;
    if (c->use_eventlog) {
#ifdef _WIN32
        return evlog_init(c);
#else
        snprintf(c->err, sizeof c->err, "The Windows Event Log backend only exists on Windows. Use -f <logfile> here.");
        return -1;
#endif
    }
    c->fp = fopen(c->path, "r");
    if (!c->fp) { snprintf(c->err, sizeof c->err, "Cannot open '%s' (does it exist? do you have permission?)", c->path); return -1; }
    if (!c->from_start) fseek(c->fp, 0, SEEK_END);
    return 0;
}

int collector_poll(Collector *c, LineCb cb, void *ud) {
    if (c->use_eventlog) {
#ifdef _WIN32
        return evlog_poll(c, cb, ud);
#else
        return -1;
#endif
    }
    char line[4096]; int n = 0, max = c->rate > 0 ? (c->rate / 4 > 0 ? c->rate / 4 : 1) : 5000;
    while (n < max && fgets(line, sizeof line, c->fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0]) continue;
        time_t ts = parse_ts(line); if (!ts) ts = time(NULL);
        cb(line, ts, ud); n++;
    }
    if (n < max) {                               /* reached EOF: detect truncation/rotation, then wait */
        c->eof_hit = 1;
        struct stat st; long pos = ftell(c->fp);
        if (stat(c->path, &st) == 0 && pos >= 0 && st.st_size < pos) {
            FILE *nf = fopen(c->path, "r"); if (nf) { fclose(c->fp); c->fp = nf; }
        }
        clearerr(c->fp);
    } else c->eof_hit = 0;
    return n;
}

void collector_close(Collector *c) { if (c->fp) fclose(c->fp); free(c->buf); c->fp = NULL; c->buf = NULL; }

/* ====================================================================
 * 5. ENGINE (tracker, correlation, detection, scoring, alerts)
 * ==================================================================== */
/* Engine: track per-source state, correlate within time windows, detect, score, alert. */

#define FEEDN 256
#define ALN 200
static Attacker src[MAXSRC];
static Config g_cfg;
static Stats g_st;
static SecurityEvent feed[FEEDN]; static int feed_total = 0;
static Alert alerts[ALN]; static int alert_total = 0;
static time_t latest_ts = 0, wall_latest = 0;
static const char *LVN[] = {"LOW", "SUSPICIOUS", "MEDIUM", "HIGH", "CRITICAL"};

const char *level_name(int lv) { return LVN[lv < 0 ? 0 : lv > 4 ? 4 : lv]; }
int level_for_score(int s) { return s >= 80 ? 4 : s >= 60 ? 3 : s >= 40 ? 2 : s >= 20 ? 1 : 0; }
void engine_init(const Config *c) { g_cfg = *c; }
const Config *engine_cfg(void) { return &g_cfg; }
const Stats *engine_stats(void) { return &g_st; }

/* Engine clock = newest event time advanced by wall time (works live and when replaying old logs). */
time_t engine_now(void) { return latest_ts ? latest_ts + (time(NULL) - wall_latest) : time(NULL); }

static int allowed(const char *ip) { for (int i = 0; i < g_cfg.nallow; i++) if (!strcmp(g_cfg.allow[i], ip)) return 1; return 0; }
static Attacker *find(const char *ip) {
    unsigned h = 5381; for (const char *c = ip; *c; c++) h = h * 33 + (unsigned char)*c;
    for (int i = 0; i < MAXSRC; i++) {
        Attacker *a = &src[(h + (unsigned)i) % MAXSRC];
        if (!a->used) { a->used = 1; snprintf(a->ip, sizeof a->ip, "%s", ip); return a; }
        if (!strcmp(a->ip, ip)) return a;
    }
    return NULL;
}
static void feed_push(const SecurityEvent *e) { feed[feed_total % FEEDN] = *e; feed_total++; }
static int count_recent(const time_t *ring, int n, time_t ref, int win) {
    int m = n < RING ? n : RING, c = 0;
    for (int i = 0; i < m; i++) { long d = (long)(ref - ring[i]); if (d <= win && d >= -30) c++; }
    return c;
}
static void add_user(Attacker *a, const char *u) {
    if (!u[0]) return;
    for (int i = 0; i < a->unique_usernames && i < MAXU; i++) if (!strcmp(a->users[i], u)) return;
    if (a->unique_usernames < MAXU) snprintf(a->users[a->unique_usernames], 64, "%s", u);
    a->unique_usernames++;
}
static void raise_alert(Attacker *a, int level, const char *rule, const char *mitre, time_t ts, const char *fmt, ...) {
    Alert al; memset(&al, 0, sizeof al);
    al.ts = ts; al.level = level;
    snprintf(al.ip, sizeof al.ip, "%s", a->ip); snprintf(al.rule, sizeof al.rule, "%s", rule); snprintf(al.mitre, sizeof al.mitre, "%s", mitre);
    va_list ap; va_start(ap, fmt); vsnprintf(al.msg, sizeof al.msg, fmt, ap); va_end(ap);
    alerts[alert_total % ALN] = al; alert_total++; g_st.alerts++;
    SecurityEvent ev; memset(&ev, 0, sizeof ev);
    ev.ts = ts; ev.type = EV_ALERT; snprintf(ev.ip, sizeof ev.ip, "%s", a->ip);
    snprintf(ev.msg, sizeof ev.msg, "%s %s %s", level_name(level), al.rule, a->ip);
    feed_push(&ev); log_alert(&al);
}

void engine_ingest(const SecurityEvent *e) {
    if (allowed(e->ip)) return;
    Attacker *a = find(e->ip); if (!a) return;
    g_st.events++;
    if (e->ts > latest_ts) { latest_ts = e->ts; wall_latest = time(NULL); }
    if (!a->first_seen) { a->first_seen = e->ts; g_st.sources++; }
    a->last_seen = e->ts;
    feed_push(e); log_event(e);
    if (e->type == EV_FAIL || e->type == EV_INVALID || e->type == EV_OK) add_user(a, e->user);

    switch (e->type) {
    case EV_CONN:
        g_st.conns++; a->connection_count++; a->conn_ring[a->conn_n++ % RING] = e->ts;
        { int c = count_recent(a->conn_ring, a->conn_n, e->ts, g_cfg.conn_window);
          if (c >= g_cfg.conn_thresh && (!a->last_burst_alert || e->ts - a->last_burst_alert > 60)) {
              a->last_burst_alert = e->ts;
              raise_alert(a, LV_MED, "CONNECTION_BURST", "T1110", e->ts, "%d connections in %ds from %s (possible automation)", c, g_cfg.conn_window, a->ip);
          } }
        break;
    case EV_FAIL:
        g_st.fails++; a->failed_logins++; a->last_fail = e->ts; a->fail_ring[a->fail_n++ % RING] = e->ts;
        { int c = count_recent(a->fail_ring, a->fail_n, e->ts, g_cfg.window);
          if (c >= g_cfg.fail_thresh && (!a->last_brute_alert || e->ts - a->last_brute_alert > 300)) {
              a->last_brute_alert = e->ts;
              raise_alert(a, LV_HIGH, "POSSIBLE_SSH_BRUTE_FORCE", "T1110", e->ts, "%d failed logins in %ds from %s (last user '%s')", c, g_cfg.window, a->ip, e->user);
          } }
        break;
    case EV_OK:
        g_st.succ++; a->successful_logins++;
        if (a->failed_logins >= 3 && e->ts - a->last_fail <= 3600) {
            a->fail_then_success = 1;
            raise_alert(a, LV_CRIT, "FAILURE_THEN_SUCCESS", "T1110", e->ts, "login SUCCEEDED as '%s' after %d failures from %s - investigate possible credential compromise", e->user, a->failed_logins, a->ip);
        }
        break;
    default: break;
    }
    if (a->unique_usernames >= g_cfg.enum_thresh && !a->enum_alerted) {
        a->enum_alerted = 1;
        raise_alert(a, LV_MED, "USERNAME_ENUMERATION", "T1110", e->ts, "%d different usernames tried from %s (account discovery / spraying signal)", a->unique_usernames, a->ip);
    }
}

/* Explainable score: every component is stored so the UI can show exactly why. */
void engine_tick(void) {
    time_t now = engine_now();
    for (int i = 0; i < MAXSRC; i++) {
        Attacker *a = &src[i]; if (!a->used || !a->first_seen) continue;
        a->recent_fails = count_recent(a->fail_ring, a->fail_n, now, g_cfg.window);
        a->burst = count_recent(a->conn_ring, a->conn_n, now, g_cfg.conn_window) >= g_cfg.conn_thresh;
        a->pts_fail = a->recent_fails * 6; if (a->pts_fail > 40) a->pts_fail = 40;
        a->pts_users = a->unique_usernames > 1 ? (a->unique_usernames - 1) * 5 : 0; if (a->pts_users > 20) a->pts_users = 20;
        int burst_recent = a->burst || (a->last_burst_alert && now - a->last_burst_alert <= 900);
        a->pts_burst = burst_recent ? 15 : 0;
        a->pts_alert = (a->last_brute_alert && now - a->last_brute_alert <= 900) ? 25 : 0;   /* brute-force alert in last 15 min */
        a->pts_seq = a->fail_then_success ? 30 : 0;
        a->pts_hist = a->failed_logins > 10 ? 10 : a->failed_logins;
        int s = a->pts_fail + a->pts_users + a->pts_burst + a->pts_seq + a->pts_hist + a->pts_alert;
        a->threat_score = s > 100 ? 100 : s;
    }
}

static int cmp_src(const void *x, const void *y) {
    const Attacker *a = *(Attacker *const *)x, *b = *(Attacker *const *)y;
    if (b->threat_score != a->threat_score) return b->threat_score - a->threat_score;
    return b->failed_logins - a->failed_logins;
}
int engine_sources_sorted(Attacker **out, int max) {
    int n = 0;
    for (int i = 0; i < MAXSRC && n < max; i++) if (src[i].used && src[i].first_seen) out[n++] = &src[i];
    qsort(out, (size_t)n, sizeof out[0], cmp_src);
    return n;
}
int engine_global_score(void) { int m = 0; for (int i = 0; i < MAXSRC; i++) if (src[i].used && src[i].threat_score > m) m = src[i].threat_score; return m; }
int engine_alert_count(void) { return alert_total < ALN ? alert_total : ALN; }
const Alert *engine_alert_recent(int i) { return &alerts[(alert_total - 1 - i + ALN * 2) % ALN]; }
int engine_feed_count(void) { return feed_total < FEEDN ? feed_total : FEEDN; }
const SecurityEvent *engine_feed_recent(int i) { return &feed[(feed_total - 1 - i + FEEDN * 2) % FEEDN]; }
int engine_feed_total(void) { return feed_total; }
const SecurityEvent *engine_feed_abs(int idx) { return &feed[idx % FEEDN]; }

/* ====================================================================
 * 6. LOGGER (alerts.csv, events.csv, report.json)
 * ==================================================================== */
static void fmt_time(time_t t, char *o, size_t n, const char *fmt) { struct tm *tm = localtime(&t); strftime(o, n, fmt, tm); }

void log_init(void) {
    FILE *f;
    if ((f = fopen("alerts.csv", "r"))) fclose(f);
    else if ((f = fopen("alerts.csv", "w"))) { fputs("time,level,rule,mitre,ip,message\n", f); fclose(f); }
    if ((f = fopen("events.csv", "r"))) fclose(f);
    else if ((f = fopen("events.csv", "w"))) { fputs("time,type,ip,user\n", f); fclose(f); }
}
void log_event(const SecurityEvent *e) {
    static const char *T[] = {"NONE", "CONN", "FAIL", "OK", "INVALID", "DISC", "ALERT"};
    FILE *f = fopen("events.csv", "a"); if (!f) return;
    char ts[32]; fmt_time(e->ts, ts, sizeof ts, "%Y-%m-%d %H:%M:%S");
    fprintf(f, "%s,%s,%s,%s\n", ts, T[e->type], e->ip, e->user); fclose(f);
}
void log_alert(const Alert *a) {
    FILE *f = fopen("alerts.csv", "a"); if (!f) return;
    char ts[32]; fmt_time(a->ts, ts, sizeof ts, "%Y-%m-%d %H:%M:%S");
    fprintf(f, "%s,%s,%s,%s,%s,\"%s\"\n", ts, level_name(a->level), a->rule, a->mitre, a->ip, a->msg); fclose(f);
}
static void js(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) { if (*s == '"' || *s == '\\') fputc('\\', f); if ((unsigned char)*s >= 32) fputc(*s, f); }
    fputc('"', f);
}
int log_export_report(const char *path) {
    FILE *f = fopen(path, "w"); if (!f) return 0;
    const Stats *s = engine_stats(); char ts[32];
    fmt_time(engine_now(), ts, sizeof ts, "%Y-%m-%d %H:%M:%S");
    fprintf(f, "{\n  \"generated\": \"%s\",\n  \"threat_level\": \"%s\",\n", ts, level_name(level_for_score(engine_global_score())));
    fprintf(f, "  \"events\": %ld, \"connections\": %ld, \"failed_logins\": %ld, \"successful_logins\": %ld, \"sources\": %d, \"alerts\": %ld,\n",
            s->events, s->conns, s->fails, s->succ, s->sources, s->alerts);
    fputs("  \"sources\": [\n", f);
    static Attacker *list[MAXSRC]; int n = engine_sources_sorted(list, MAXSRC);
    for (int i = 0; i < n; i++) {
        Attacker *a = list[i];
        fputs("    {\"ip\": ", f); js(f, a->ip);
        fprintf(f, ", \"score\": %d, \"level\": \"%s\", \"failed\": %d, \"success\": %d, \"connections\": %d, \"usernames\": %d, "
                   "\"why\": {\"failures_in_window\": %d, \"usernames\": %d, \"connection_burst\": %d, \"failure_then_success\": %d, \"history\": %d, \"recent_brute_alert\": %d}}%s\n",
                a->threat_score, level_name(level_for_score(a->threat_score)), a->failed_logins, a->successful_logins, a->connection_count,
                a->unique_usernames, a->pts_fail, a->pts_users, a->pts_burst, a->pts_seq, a->pts_hist, a->pts_alert, i + 1 < n ? "," : "");
    }
    fputs("  ],\n  \"alerts\": [\n", f);
    int an = engine_alert_count();
    for (int i = 0; i < an; i++) {
        const Alert *a = engine_alert_recent(an - 1 - i);
        fmt_time(a->ts, ts, sizeof ts, "%Y-%m-%d %H:%M:%S");
        fprintf(f, "    {\"time\": \"%s\", \"level\": \"%s\", \"rule\": ", ts, level_name(a->level)); js(f, a->rule);
        fputs(", \"mitre\": ", f); js(f, a->mitre); fputs(", \"ip\": ", f); js(f, a->ip); fputs(", \"message\": ", f); js(f, a->msg);
        fprintf(f, "}%s\n", i + 1 < an ? "," : "");
    }
    fputs("  ]\n}\n", f); fclose(f);
    return 1;
}

/* ====================================================================
 * 7. TERMINAL UI (live dashboard)
 * ==================================================================== */
/* Terminal UI: redraws the same screen (no scrolling) using ANSI/VT sequences. */

#define W 76
static char out[1 << 16]; static size_t on;
static const char *LVC[] = {GRN, CYN, YEL, MAG, CRITC};

static void put(const char *s) { size_t l = strlen(s); if (on + l < sizeof out - 1) { memcpy(out + on, s, l); on += l; out[on] = 0; } }
static void rule(char c) { char t[W + 8]; t[0] = '+'; memset(t + 1, c, W + 2); t[W + 3] = '+'; t[W + 4] = 0; put(t); put("\033[K\n"); }
static void row(const char *txt) {         /* pad/truncate to W visible columns, ignoring colour escapes */
    char tmp[2048]; size_t t = 0; int vis = 0; const char *p = txt;
    while (*p && t < sizeof tmp - 16) {
        if (*p == '\033') { while (*p && *p != 'm') tmp[t++] = *p++; if (*p) tmp[t++] = *p++; continue; }
        if (vis < W) { tmp[t++] = *p; vis++; }
        p++;
    }
    tmp[t] = 0; put("| "); put(tmp); put(RST);
    for (; vis < W; vis++) put(" ");
    put(" |\033[K\n");
}
static void hms(time_t t, char *o, size_t n) { struct tm *tm = localtime(&t); strftime(o, n, "%H:%M:%S", tm); }

void ui_fmt_event(char *o, size_t sz, const SecurityEvent *e, int color) {
    char ts[16]; hms(e->ts, ts, sizeof ts);
    const char *c1 = "", *c2 = "", *r = "";
    if (color) { r = RST; }
    switch (e->type) {
    case EV_CONN:    if (color) c1 = CYN; snprintf(o, sz, "%s%s [CONN]%s  %s -> TCP/22", DIM, ts, r, e->ip); (void)c1; (void)c2; break;
    case EV_FAIL:    snprintf(o, sz, "%s%s%s %s[FAIL]%s  %s@%s", color ? DIM : "", ts, r, color ? YEL : "", r, e->user, e->ip); break;
    case EV_OK:      snprintf(o, sz, "%s%s%s %s[OK]%s    %s@%s logged in", color ? DIM : "", ts, r, color ? GRN : "", r, e->user, e->ip); break;
    case EV_INVALID: snprintf(o, sz, "%s%s%s %s[INVL]%s  invalid user %s@%s", color ? DIM : "", ts, r, color ? YEL : "", r, e->user, e->ip); break;
    case EV_DISC:    snprintf(o, sz, "%s%s%s [DISC]  %s", color ? DIM : "", ts, r, e->ip); break;
    case EV_ALERT:   snprintf(o, sz, "%s%s%s %s[ALERT]%s %s", color ? DIM : "", ts, r, color ? RED BOLD : "", r, e->msg); break;
    default:         snprintf(o, sz, "%s", ts);
    }
}

static void bar(char *o, int score) { int f = score / 10; for (int i = 0; i < 10; i++) o[i] = i < f ? '#' : '-'; o[10] = 0; }

static void header(int ssh_online, int paused) {
    const Stats *s = engine_stats(); const Config *c = engine_cfg(); char t[512];
    int g = engine_global_score(), lv = level_for_score(g);
    rule('=');
    snprintf(t, sizeof t, BOLD CYN "DARKWATCH :: REAL-TIME SSH THREAT MONITOR" RST "%s", paused ? "                           " YEL "[PAUSED]" RST : "                             " GRN "[LIVE]" RST);
    row(t); rule('=');
    snprintf(t, sizeof t, "SSH: %s%s" RST "   PORT: %d   THREAT: %s%s" RST " (%d)   EVENTS: %ld",
             ssh_online ? GRN : RED, ssh_online ? "ONLINE" : "OFFLINE", c->port, LVC[lv], level_name(lv), g, s->events);
    row(t);
    snprintf(t, sizeof t, "Connections: %ld   Failed: %ld   Logins OK: %ld   Sources: %d   Alerts: %ld",
             s->conns, s->fails, s->succ, s->sources, s->alerts);
    row(t); rule('-');
}
static void footer(const char *source) {
    char t[300]; rule('-');
    snprintf(t, sizeof t, DIM "[1]Dashboard [2]Events [3]Alerts [4]Sources [x]Export [p]Pause [q]Quit" RST);
    row(t);
    snprintf(t, sizeof t, DIM "Source: %.60s" RST, source); row(t); rule('=');
}

void ui_draw(int view, int ssh_online, const char *source, int paused) {
    char t[700], e[400], b[16]; static Attacker *list[MAXSRC];
    on = 0; out[0] = 0; put("\033[H");
    header(ssh_online, paused);
    int n = engine_sources_sorted(list, MAXSRC);

    if (view == 1) {
        row(BOLD "LIVE EVENTS" RST);
        int cnt = engine_feed_count(); if (cnt > 10) cnt = 10;
        for (int i = cnt - 1; i >= 0; i--) { ui_fmt_event(e, sizeof e, engine_feed_recent(i), 1); row(e); }
        for (int i = cnt; i < 10; i++) row("");
        rule('-'); row(BOLD "ACTIVE THREATS" RST);
        for (int i = 0; i < 4; i++) {
            if (i < n) {
                Attacker *a = list[i]; bar(b, a->threat_score); int lv = level_for_score(a->threat_score);
                snprintf(t, sizeof t, "%-18.18s fails:%-4d users:%-3d conns:%-4d [%s] %s%3d %s" RST, a->ip, a->failed_logins,
                         a->unique_usernames, a->connection_count, b, LVC[lv], a->threat_score, level_name(lv));
                row(t);
            } else row("");
        }
    } else if (view == 2) {
        row(BOLD "ALL RECENT EVENTS (newest at bottom)" RST);
        int cnt = engine_feed_count(); if (cnt > 20) cnt = 20;
        for (int i = cnt - 1; i >= 0; i--) { ui_fmt_event(e, sizeof e, engine_feed_recent(i), 1); row(e); }
        for (int i = cnt; i < 20; i++) row("");
    } else if (view == 3) {
        row(BOLD "ALERTS (newest first)" RST);
        int cnt = engine_alert_count(); if (cnt > 9) cnt = 9;
        for (int i = 0; i < 9; i++) {
            if (i < cnt) {
                const Alert *a = engine_alert_recent(i); char ts[16]; hms(a->ts, ts, sizeof ts);
                snprintf(t, sizeof t, DIM "%s" RST " %s%-10s" RST " %s %s", ts, LVC[a->level], level_name(a->level), a->mitre, a->rule);
                row(t);
                snprintf(t, sizeof t, "   %s", a->msg); row(t);
            } else { row(""); row(""); }
        }
    } else {
        row(BOLD "SOURCES (ranked by threat score)" RST);
        snprintf(t, sizeof t, DIM "%-20s %5s %6s %5s %5s %6s %s" RST, "IP", "FAIL", "WINDOW", "USERS", "OK", "CONNS", "SCORE");
        row(t);
        for (int i = 0; i < 10; i++) {
            if (i < n) {
                Attacker *a = list[i]; int lv = level_for_score(a->threat_score);
                snprintf(t, sizeof t, "%-20.20s %5d %6d %5d %5d %6d %s%3d %s" RST, a->ip, a->failed_logins, a->recent_fails,
                         a->unique_usernames, a->successful_logins, a->connection_count, LVC[lv], a->threat_score, level_name(lv));
                row(t);
            } else row("");
        }
        rule('-');
        if (n > 0) {
            Attacker *a = list[0];
            snprintf(t, sizeof t, BOLD "WHY %s SCORED %d" RST, a->ip, a->threat_score); row(t);
            snprintf(t, sizeof t, "  failures in last %ds: %d x6 = %d (cap 40)", engine_cfg()->window, a->recent_fails, a->pts_fail); row(t);
            snprintf(t, sizeof t, "  distinct usernames: %d -> %d (cap 20)   connection burst: %d", a->unique_usernames, a->pts_users, a->pts_burst); row(t);
            snprintf(t, sizeof t, "  failure->success: %d   lifetime failures: %d (cap 10)   brute-force alert <15m: %d", a->pts_seq, a->pts_hist, a->pts_alert); row(t);
        } else { row("No sources observed yet."); row(""); row(""); row(""); }
    }
    footer(source);
    put("\033[J");
    fwrite(out, 1, on, stdout); fflush(stdout);
}

/* ====================================================================
 * 8. MAIN
 * ==================================================================== */
static volatile sig_atomic_t running = 1;
static void on_sig(int s) { (void)s; running = 0; }
static void on_line(const char *line, time_t ts, void *ud) {
    (void)ud; SecurityEvent e;
    if (parse_line(line, ts, &e)) engine_ingest(&e);
}
static void usage(const char *p) {
    printf("DARKWATCH %s - real-time SSH attack monitor\n\n"
           "usage: %s [options]\n"
#ifdef _WIN32
           "  (default source: Windows Event Log 'OpenSSH/Operational' - run as Administrator)\n"
#else
           "  (on this OS you must give -f <logfile>)\n"
#endif
           "  -f FILE        tail a log file instead (e.g. C:\\ProgramData\\ssh\\logs\\sshd.log)\n"
           "  --from-start   process existing history first (default: only new events)\n"
           "  --rate N       replay at most N lines/second (demo of old logs)\n"
           "  -n N           failures that trigger brute-force alert (default 5)\n"
           "  -w SEC         brute-force time window in seconds (default 60)\n"
           "  --conn N       connections in 10s that trigger burst alert (default 15)\n"
           "  --enum N       distinct usernames that trigger enumeration alert (default 4)\n"
           "  --port P       SSH port to health-check on localhost (default 22)\n"
           "  --allow IP     ignore this IP (repeatable, up to 16)\n"
           "  --headless     no dashboard, print events/alerts as plain lines\n"
           "  --oneshot      with -f: analyse the file, print summary, exit\n", DW_VERSION, p);
}

int main(int argc, char **argv) {
    Config cfg; memset(&cfg, 0, sizeof cfg);
    cfg.fail_thresh = 5; cfg.window = 60; cfg.conn_thresh = 15; cfg.conn_window = 10; cfg.enum_thresh = 4; cfg.port = 22;
    Collector col; memset(&col, 0, sizeof col);
#ifdef _WIN32
    col.use_eventlog = 1;
#endif
    int headless = 0, oneshot = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-f") && i + 1 < argc) { col.use_eventlog = 0; snprintf(col.path, sizeof col.path, "%s", argv[++i]); }
        else if (!strcmp(argv[i], "--from-start")) col.from_start = 1;
        else if (!strcmp(argv[i], "--rate") && i + 1 < argc) col.rate = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) cfg.fail_thresh = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) cfg.window = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--conn") && i + 1 < argc) cfg.conn_thresh = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--enum") && i + 1 < argc) cfg.enum_thresh = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) cfg.port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--allow") && i + 1 < argc && cfg.nallow < 16) snprintf(cfg.allow[cfg.nallow++], 46, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--headless")) headless = 1;
        else if (!strcmp(argv[i], "--oneshot")) { oneshot = 1; headless = 1; col.from_start = 1; }
        else { usage(argv[0]); return !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") ? 0 : 2; }
    }
    if (cfg.fail_thresh < 2) cfg.fail_thresh = 2;
    if (cfg.window < 1) cfg.window = 1;
    if (!col.use_eventlog && !col.path[0]) { usage(argv[0]); return 2; }
    if (oneshot && col.use_eventlog) { fprintf(stderr, "--oneshot needs -f <logfile>\n"); return 2; }

    engine_init(&cfg); log_init();
    if (collector_init(&col) != 0) { fprintf(stderr, "darkwatch: %s\n", col.err); return 1; }
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    plat_init(!headless);

    char source[300];
    if (col.use_eventlog) snprintf(source, sizeof source, "Windows Event Log: OpenSSH/Operational (live)");
    else snprintf(source, sizeof source, "File: %s", col.path);

    int view = 1, paused = 0, ssh_online = 0, printed = 0, rc = 0; time_t last_port = 0;
    if (headless) printf("DARKWATCH %s headless | %s | rule: %d failures / %ds\n", DW_VERSION, source, cfg.fail_thresh, cfg.window);

    while (running) {
        int n = collector_poll(&col, on_line, NULL);
        if (n < 0) { running = 0; rc = 1; break; }
        engine_tick();
        time_t wall = time(NULL);
        if (wall - last_port >= 5) { ssh_online = plat_port_open(cfg.port); last_port = wall; }
        if (headless) {
            int total = engine_feed_total(); if (total - printed > 256) printed = total - 256;
            for (; printed < total; printed++) { char l[500]; ui_fmt_event(l, sizeof l, engine_feed_abs(printed), 0); printf("%s\n", l); }
            fflush(stdout);
            if (oneshot && col.eof_hit) break;
        } else {
            int k, redraw=0;
            while ((k = plat_key()) != -1) {
                redraw = 1;
                if (k == 'q' || k == 'Q') running = 0;
                else if (k >= '1' && k <= '4') view = k - '0';
                else if (k == 'p' || k == 'P') paused = !paused;
                else if (k == 'x' || k == 'X') log_export_report("report.json");
            }
            if (!paused) ui_draw(view, ssh_online, source, 0);
            else if (redraw) ui_draw(view, ssh_online, source, 1);
        }
        plat_sleep_ms(250);
    }
    plat_shutdown();
    if (col.err[0] && rc) fprintf(stderr, "darkwatch: %s\n", col.err);
    const Stats *s = engine_stats();
    printf("\nDARKWATCH summary: %ld events, %ld connections, %ld failed, %ld successful logins, %d sources, %ld alerts, threat %s (%d)\n",
           s->events, s->conns, s->fails, s->succ, s->sources, s->alerts, level_name(level_for_score(engine_global_score())), engine_global_score());
    static Attacker *list[MAXSRC]; int cnt = engine_sources_sorted(list, MAXSRC);
    for (int i = 0; i < cnt && i < 5; i++)
        printf("  %-18s score %3d %-10s fails %d users %d ok %d\n", list[i]->ip, list[i]->threat_score, level_name(level_for_score(list[i]->threat_score)),
               list[i]->failed_logins, list[i]->unique_usernames, list[i]->successful_logins);
    if (headless || s->events) { log_export_report("report.json"); printf("Files: alerts.csv, events.csv, report.json\n"); }
    collector_close(&col);
    return rc;
}
