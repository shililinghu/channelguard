/* ChannelGuard: apply an assigned parent's rule to cross-directory child processes.
 * Runs while evaluating the first packet, before it can pass through unassigned.
 * Static folder rules also cover launcher-independent service/game processes.
 */
#include "pb_internal.h"
#include <tlhelp32.h>

typedef struct { DWORD pid, parent; } CG_PARENT;
static CG_PARENT cg_parents[4096];
static DWORD cg_parent_count, cg_parent_tick;
static SRWLOCK cg_parent_lock = SRWLOCK_INIT;

static DWORD cg_parent(DWORD pid, BOOL force)
{
    DWORD result=0;
    AcquireSRWLockExclusive(&cg_parent_lock);
    if (force || GetTickCount()-cg_parent_tick > 200 || !cg_parent_tick) {
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W entry={0}; entry.dwSize=sizeof(entry);
            cg_parent_count=0;
            if (Process32FirstW(snap,&entry)) do {
                if (cg_parent_count < 4096) {
                    cg_parents[cg_parent_count].pid=entry.th32ProcessID;
                    cg_parents[cg_parent_count++].parent=entry.th32ParentProcessID;
                }
            } while (Process32NextW(snap,&entry));
            CloseHandle(snap); cg_parent_tick=GetTickCount();
        }
    }
    for (DWORD i=0;i<cg_parent_count;i++) if (cg_parents[i].pid==pid) {result=cg_parents[i].parent;break;}
    ReleaseSRWLockExclusive(&cg_parent_lock);
    return result;
}

static BOOL cg_created(DWORD pid, ULARGE_INTEGER *created)
{
    HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    FILETIME start,exit,kernel,user;
    if (!process) return FALSE;
    BOOL ok=GetProcessTimes(process,&start,&exit,&kernel,&user);
    CloseHandle(process);
    if (ok) {created->LowPart=start.dwLowDateTime;created->HighPart=start.dwHighDateTime;}
    return ok;
}

RuleAction cg_ancestor_rule(DWORD pid, UINT32 destination, const UINT8 *destination6,
                           UINT16 port, BOOL udp, UINT32 *config_id)
{
    ULARGE_INTEGER child_time,parent_time;
    if (!cg_created(pid,&child_time)) return RULE_ACTION_DIRECT;
    for (int depth=0;depth<16;depth++) {
        DWORD parent=cg_parent(pid,FALSE);
        if (!parent && depth==0) parent=cg_parent(pid,TRUE);
        if (!parent || parent==pid || !cg_created(parent,&parent_time) || parent_time.QuadPart>child_time.QuadPart) break;
        char path[MAX_PROCESS_NAME];
        if (get_process_name_from_pid(parent,path,sizeof(path))) {
            RuleAction action=destination6 ? match_rule_v6(path,destination6,port,udp,config_id)
                                          : match_rule(path,destination,port,udp,config_id);
            if (action!=RULE_ACTION_DIRECT || g_tl_rule_id!=0) return action;
        }
        pid=parent; child_time=parent_time;
    }
    return RULE_ACTION_DIRECT;
}
