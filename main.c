/* Reincarnation Server.  This servers starts new system services and detects
 * they are exiting.   In case of errors, system services can be restarted.  
 * The RS server periodically checks the status of all registered services
 * services to see whether they are still alive.   The system services are 
 * expected to periodically send a heartbeat message. 
 * 
 * Changes:
 *   Nov 22, 2009: rewrite of boot process (Cristiano Giuffrida)
 *   Jul 22, 2005: Created  (Jorrit N. Herder)
 */
#include "inc.h"
#include <fcntl.h>
#include "kernel/const.h"
#include "kernel/type.h"
#include "kernel/proc.h"

/* Declare some local functions. */
static void boot_image_info_lookup( endpoint_t endpoint, struct
	boot_image *image, struct boot_image **ip, struct boot_image_priv **pp,
	struct boot_image_sys **sp, struct boot_image_dev **dp);
static void catch_boot_init_ready(endpoint_t endpoint);
static void get_work(message *m_ptr, int *status_ptr);

/* SEF functions and variables. */
static void sef_local_startup(void);
static int sef_cb_init_fresh(int type, sef_init_info_t *info);
static int sef_cb_init_restart(int type, sef_init_info_t *info);
static int sef_cb_init_lu(int type, sef_init_info_t *info);
static int sef_cb_init_response(message *m_ptr);
static int sef_cb_lu_response(message *m_ptr);
static void sef_cb_signal_handler(int signo);
static int sef_cb_signal_manager(endpoint_t target, int signo);


/*===========================================================================*
 *				main                                         *
 *===========================================================================*/
#define EDONTREPLY (-1001)
#define RS_UP 1
#define RS_DOWN 2
#define RS_REFRESH 3
#define RS_RESTART 4
#define RS_SHUTDOWN 5
#define RS_UPDATE 6
#define RS_CLONE 7
#define RS_UNCLONE 8
#define RS_EDIT 9
#define RS_SYSCTL 10
#define RS_FI 11
#define RS_GETSYSINFO 12
#define RS_LOOKUP 13
#define RS_INIT 14
#define RS_LU_PREPARE 15

static void initialize_service(void)
{
    int s;
    sef_local_startup();
    
    if (OK != (s = sys_getmachine(&machine)))
        panic("couldn't get machine info: %d", s);
}

static void validate_message_source(int who_e, int *who_p)
{
    if (rs_isokendpt(who_e, who_p) != OK) {
        panic("message from bogus source: %d", who_e);
    }
}

static void handle_clock_notification(message *m)
{
    do_period(m);
}

static void handle_heartbeat_notification(int who_p, message *m)
{
    if (rproc_ptr[who_p] != NULL) {
        rproc_ptr[who_p]->r_alive_tm = m->m_notify.timestamp;
    } else {
        printf("RS: warning: got unexpected notify message from %d\n", m->m_source);
    }
}

static void process_notification(int who_p, message *m)
{
    if (who_p == CLOCK) {
        handle_clock_notification(m);
    } else {
        handle_heartbeat_notification(who_p, m);
    }
}

static int process_user_request(int call_nr, message *m)
{
    switch (call_nr) {
    case RS_UP:         return do_up(m);
    case RS_DOWN:       return do_down(m);
    case RS_REFRESH:    return do_refresh(m);
    case RS_RESTART:    return do_restart(m);
    case RS_SHUTDOWN:   return do_shutdown(m);
    case RS_UPDATE:     return do_update(m);
    case RS_CLONE:      return do_clone(m);
    case RS_UNCLONE:    return do_unclone(m);
    case RS_EDIT:       return do_edit(m);
    case RS_SYSCTL:     return do_sysctl(m);
    case RS_FI:         return do_fi(m);
    case RS_GETSYSINFO: return do_getsysinfo(m);
    case RS_LOOKUP:     return do_lookup(m);
    case RS_INIT:       return do_init_ready(m);
    case RS_LU_PREPARE: return do_upd_ready(m);
    default:
        printf("RS: warning: got unexpected request %d from %d\n", m->m_type, m->m_source);
        return ENOSYS;
    }
}

static void send_reply_if_needed(int result, int who_e, message *m)
{
    if (result != EDONTREPLY) {
        m->m_type = result;
        reply(who_e, NULL, m);
    }
}

static void handle_request(message *m, int who_e)
{
    int result = process_user_request(m->m_type, m);
    send_reply_if_needed(result, who_e, m);
}

int main(void)
{
    message m;
    int ipc_status;
    int who_e, who_p;

    initialize_service();

    while (TRUE) {
        rs_idle_period();
        get_work(&m, &ipc_status);
        
        who_e = m.m_source;
        validate_message_source(who_e, &who_p);

        if (is_ipc_notify(ipc_status)) {
            process_notification(who_p, &m);
        } else {
            handle_request(&m, who_e);
        }
    }
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
static void register_init_callbacks(void)
{
    sef_setcb_init_fresh(sef_cb_init_fresh);
    sef_setcb_init_restart(sef_cb_init_restart);
    sef_setcb_init_lu(sef_cb_init_lu);
}

static void register_response_callbacks(void)
{
    sef_setcb_init_response(sef_cb_init_response);
    sef_setcb_lu_response(sef_cb_lu_response);
}

static void register_signal_callbacks(void)
{
    sef_setcb_signal_handler(sef_cb_signal_handler);
    sef_setcb_signal_manager(sef_cb_signal_manager);
}

static void sef_local_startup(void)
{
    register_init_callbacks();
    register_response_callbacks();
    register_signal_callbacks();
    sef_startup();
}

/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
static int count_system_services(struct boot_image *image) {
    int count = 0;
    for (int i = 0; i < NR_BOOT_PROCS; i++) {
        if (!iskerneln(_ENDPOINT_P(image[i].endpoint))) {
            count++;
        }
    }
    return count;
}

static int count_priv_table_services(void) {
    int count = 0;
    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        if (!iskerneln(_ENDPOINT_P(boot_image_priv_table[i].endpoint))) {
            count++;
        }
    }
    return count;
}

static void reset_process_table(void) {
    for (struct rproc *rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
        rp->r_flags = 0;
        rp->r_init_err = ERESTART;
        rp->r_pub = &rprocpub[rp - rproc];
        rp->r_pub->in_use = FALSE;
        rp->r_pub->old_endpoint = NONE;
        rp->r_pub->new_endpoint = NONE;
    }
}

static void set_privilege_structure(struct rproc *rp, struct boot_image *ip, 
                                   struct boot_image_priv *boot_image_priv) {
    int all_c[] = { ALL_C, NULL_C };
    int no_c[] = { NULL_C };
    int *calls;
    int ipc_to;
    int s;

    rp->r_priv.s_id = static_priv_id(_ENDPOINT_P(boot_image_priv->endpoint));
    rp->r_priv.s_flags = boot_image_priv->flags;
    rp->r_priv.s_init_flags = SRV_OR_USR(rp, SRV_I, USR_I);
    rp->r_priv.s_trap_mask = SRV_OR_USR(rp, SRV_T, USR_T);
    ipc_to = SRV_OR_USR(rp, SRV_M, USR_M);
    fill_send_mask(&rp->r_priv.s_ipc_to, ipc_to == ALL_M);
    rp->r_priv.s_sig_mgr = SRV_OR_USR(rp, SRV_SM, USR_SM);
    rp->r_priv.s_bak_sig_mgr = NONE;
    
    calls = SRV_OR_USR(rp, SRV_KC, USR_KC) == ALL_C ? all_c : no_c;
    fill_call_mask(calls, NR_SYS_CALLS, rp->r_priv.s_k_call_mask, KERNEL_CALL, TRUE);

    if (boot_image_priv->endpoint != RS_PROC_NR && 
        boot_image_priv->endpoint != VM_PROC_NR) {
        if ((s = sys_privctl(ip->endpoint, SYS_PRIV_SET_SYS, &(rp->r_priv))) != OK) {
            panic("unable to set privilege structure: %d", s);
        }
    }

    if ((s = sys_getpriv(&(rp->r_priv), ip->endpoint)) != OK) {
        panic("unable to synch privilege structure: %d", s);
    }
}

static void initialize_service_properties(struct rproc *rp, struct rprocpub *rpub,
                                         struct boot_image *ip, 
                                         struct boot_image_sys *boot_image_sys,
                                         struct boot_image_dev *boot_image_dev) {
    int all_c[] = { ALL_C, NULL_C };
    int no_c[] = { NULL_C };
    int *calls;

    strcpy(rpub->label, boot_image_priv_table[rp - rproc].label);
    rpub->sys_flags = boot_image_sys->flags;
    rpub->dev_nr = boot_image_dev->dev_nr;
    
    strlcpy(rp->r_cmd, ip->proc_name, sizeof(rp->r_cmd));
    rp->r_script[0] = '\0';
    build_cmd_dep(rp);
    strlcpy(rpub->proc_name, ip->proc_name, sizeof(rpub->proc_name));
    
    calls = SRV_OR_USR(rp, SRV_VC, USR_VC) == ALL_C ? all_c : no_c;
    fill_call_mask(calls, NR_VM_CALLS, rpub->vm_call_mask, VM_RQ_BASE, TRUE);
    
    rp->r_scheduler = SRV_OR_USR(rp, SRV_SCH, USR_SCH);
    rp->r_priority = SRV_OR_USR(rp, SRV_Q, USR_Q);
    rp->r_quantum = SRV_OR_USR(rp, SRV_QT, USR_QT);
    rpub->endpoint = ip->endpoint;
}

static void initialize_service_defaults(struct rproc *rp, struct rprocpub *rpub) {
    rp->r_old_rp = NULL;
    rp->r_new_rp = NULL;
    rp->r_prev_rp = NULL;
    rp->r_next_rp = NULL;
    rp->r_uid = 0;
    rp->r_check_tm = 0;
    rp->r_alive_tm = getticks();
    rp->r_stop_tm = 0;
    rp->r_asr_count = 0;
    rp->r_restarts = 0;
    rp->r_period = 0;
    rp->r_exec = NULL;
    rp->r_exec_len = 0;
    
    rp->r_flags = RS_IN_USE | RS_ACTIVE;
    rproc_ptr[_ENDPOINT_P(rpub->endpoint)] = rp;
    rpub->in_use = TRUE;
}

static void setup_system_service(struct boot_image_priv *boot_image_priv, 
                                struct boot_image *image) {
    struct boot_image *ip;
    struct boot_image_sys *boot_image_sys;
    struct boot_image_dev *boot_image_dev;
    struct rproc *rp;
    struct rprocpub *rpub;
    
    if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
        return;
    }
    
    boot_image_info_lookup(boot_image_priv->endpoint, image,
        &ip, NULL, &boot_image_sys, &boot_image_dev);
    rp = &rproc[boot_image_priv - boot_image_priv_table];
    rpub = rp->r_pub;
    
    set_privilege_structure(rp, ip, boot_image_priv);
    initialize_service_properties(rp, rpub, ip, boot_image_sys, boot_image_dev);
    initialize_service_defaults(rp, rpub);
}

static int start_boot_service(struct boot_image_priv *boot_image_priv, 
                             int *nr_uncaught_init_srvs) {
    struct rproc *rp;
    struct rprocpub *rpub;
    int s;
    
    if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
        return OK;
    }
    
    rp = &rproc[boot_image_priv - boot_image_priv_table];
    rpub = rp->r_pub;
    
    if (boot_image_priv->endpoint == RS_PROC_NR || 
        boot_image_priv->endpoint == VM_PROC_NR) {
        if ((s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags)) != OK) {
            panic("unable to initialize %d: %d", boot_image_priv->endpoint, s);
        }
        if (boot_image_priv->endpoint != RS_PROC_NR) {
            (*nr_uncaught_init_srvs)++;
        }
        return OK;
    }
    
    if ((s = sched_init_proc(rp)) != OK) {
        panic("unable to initialize scheduling: %d", s);
    }
    if ((s = sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL)) != OK) {
        panic("unable to initialize privileges: %d", s);
    }
    
    if (boot_image_priv->flags & SYS_PROC) {
        if ((s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags)) != OK) {
            panic("unable to initialize service: %d", s);
        }
        if (rpub->sys_flags & SF_SYNCH_BOOT) {
            catch_boot_init_ready(rpub->endpoint);
        } else {
            (*nr_uncaught_init_srvs)++;
        }
    }
    
    return OK;
}

static void finalize_service_initialization(void) {
    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        struct boot_image_priv *boot_image_priv = &boot_image_priv_table[i];
        
        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            continue;
        }
        
        struct rproc *rp = &rproc[boot_image_priv - boot_image_priv_table];
        struct rprocpub *rpub = rp->r_pub;
        
        rp->r_pid = getnpid(rpub->endpoint);
        if (rp->r_pid < 0) {
            panic("unable to get pid: %d", rp->r_pid);
        }
    }
}

#if USE_LIVEUPDATE
static void perform_live_update(void) {
    struct rproc *rp, *replica_rp;
    int s, pid, replica_pid;
    endpoint_t replica_endpoint;
    
    rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    if ((s = clone_slot(rp, &replica_rp)) != OK) {
        panic("unable to clone current RS instance: %d", s);
    }
    
    pid = srv_fork(0, 0);
    if (pid < 0) {
        panic("unable to fork a new RS instance: %d", pid);
    }
    replica_pid = pid ? pid : getpid();
    if ((s = getprocnr(replica_pid, &replica_endpoint)) != 0) {
        panic("unable to get replica endpoint: %d", s);
    }
    replica_rp->r_pid = replica_pid;
    replica_rp->r_pub->endpoint = replica_endpoint;
    
    if (pid == 0) {
        s = update_service(&rp, &replica_rp, RS_SWAP, 0);
        if (s != OK) {
            panic("unable to live update RS: %d", s);
        }
        cpf_reload();
        cleanup_service(rp);
        if ((s = vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0)) != OK) {
            panic("unable to pin memory for the new RS instance: %d", s);
        }
    } else {
        s = sys_privctl(replica_endpoint, SYS_PRIV_SET_SYS, &(replica_rp->r_priv));
        if (s != OK) {
            panic("unable to set privileges for the new RS instance: %d", s);
        }
        if ((s = sched_init_proc(replica_rp)) != OK) {
            panic("unable to initialize RS replica scheduling: %d", s);
        }
        s = sys_privctl(replica_endpoint, SYS_PRIV_YIELD, NULL);
        if (s != OK) {
            panic("unable to yield control to the new RS instance: %d", s);
        }
        NOT_REACHABLE;
    }
}
#endif

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info)) {
    struct boot_image image[NR_BOOT_PROCS];
    int s, nr_uncaught_init_srvs;
    
    env_parse("rs_verbose", "d", 0, &rs_verbose, 0, 1);
    
    if ((s = sys_getinfo(GET_HZ, &system_hz, sizeof(system_hz), 0, 0)) != OK) {
        panic("Cannot get system timer frequency\n");
    }
    
    rinit.rproctab_gid = cpf_grant_direct(ANY, (vir_bytes) rprocpub,
        sizeof(rprocpub), CPF_READ);
    if (!GRANT_VALID(rinit.rproctab_gid)) {
        panic("unable to create rprocpub table grant: %d", rinit.rproctab_gid);
    }
    
    RUPDATE_INIT();
    shutting_down = FALSE;
    
    if ((s = sys_getimage(image)) != OK) {
        panic("unable to get copy of boot image table: %d", s);
    }
    
    int nr_image_srvs = count_system_services(image);
    int nr_image_priv_srvs = count_priv_table_services();
    
    if (nr_image_srvs != nr_image_priv_srvs) {
        panic("boot image table and boot image priv table mismatch");
    }
    
    reset_process_table();
    
    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        setup_system_service(&boot_image_priv_table[i], image);
    }
    
    nr_uncaught_init_srvs = 0;
    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        start_boot_service(&boot_image_priv_table[i], &nr_uncaught_init_srvs);
    }
    
    while (nr_uncaught_init_srvs) {
        catch_boot_init_ready(ANY);
        nr_uncaught_init_srvs--;
    }
    
    finalize_service_initialization();
    
    if (OK != (s = sys_setalarm(RS_DELTA_T, 0))) {
        panic("couldn't set alarm: %d", s);
    }
    
#if USE_LIVEUPDATE
    perform_live_update();
#endif
    
    return OK;
}

/*===========================================================================*
 *		            sef_cb_init_restart                              *
 *===========================================================================*/
static int perform_state_transfer(int type, sef_init_info_t *info)
{
    int r = SEF_CB_INIT_RESTART_STATEFUL(type, info);
    if (r != OK) {
        printf("SEF_CB_INIT_RESTART_STATEFUL failed: %d\n", r);
    }
    return r;
}

static void handle_update_in_progress(struct rproc *old_rs_rp)
{
    if (SRV_IS_UPDATING(old_rs_rp)) {
        end_update(ERESTART, RS_REPLY);
    }
}

static int perform_service_update(struct rproc *old_rs_rp, struct rproc *new_rs_rp)
{
    int r = update_service(&old_rs_rp, &new_rs_rp, RS_DONTSWAP, 0);
    if (r != OK) {
        printf("update_service failed: %d\n", r);
    }
    return r;
}

static int initialize_new_service(struct rproc *new_rs_rp)
{
    int r = init_service(new_rs_rp, SEF_INIT_RESTART, 0);
    if (r != OK) {
        printf("init_service failed: %d\n", r);
    }
    return r;
}

static int reschedule_alarm(void)
{
    int r = sys_setalarm(RS_DELTA_T, 0);
    if (r != OK) {
        panic("couldn't set alarm: %d", r);
    }
    return r;
}

static int sef_cb_init_restart(int type, sef_init_info_t *info)
{
    int r;
    struct rproc *old_rs_rp, *new_rs_rp;

    assert(info->endpoint == RS_PROC_NR);

    r = perform_state_transfer(type, info);
    if (r != OK) {
        return r;
    }

    old_rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    new_rs_rp = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];
    
    if (rs_verbose) {
        printf("RS: %s is the new RS after restart\n", srv_to_string(new_rs_rp));
    }

    handle_update_in_progress(old_rs_rp);

    r = perform_service_update(old_rs_rp, new_rs_rp);
    if (r != OK) {
        return r;
    }

    r = initialize_new_service(new_rs_rp);
    if (r != OK) {
        return r;
    }

    reschedule_alarm();

    return OK;
}

/*===========================================================================*
 *		              sef_cb_init_lu                                 *
 *===========================================================================*/
static int perform_default_state_transfer(int type, sef_init_info_t *info)
{
    sef_setcb_init_restart(SEF_CB_INIT_RESTART_STATEFUL);
    int r = SEF_CB_INIT_LU_DEFAULT(type, info);
    if(r != OK) {
        printf("SEF_CB_INIT_LU_DEFAULT failed: %d\n", r);
    }
    return r;
}

static int transfer_rs_control(sef_init_info_t *info)
{
    struct rproc *old_rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    struct rproc *new_rs_rp = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];
    
    if(rs_verbose) {
        printf("RS: %s is the new RS after live update\n",
            srv_to_string(new_rs_rp));
    }
    
    int r = update_service(&old_rs_rp, &new_rs_rp, RS_DONTSWAP, 0);
    if(r != OK) {
        printf("update_service failed: %d\n", r);
    }
    return r;
}

static void validate_update_state(void)
{
    assert(RUPDATE_IS_UPDATING());
    assert(RUPDATE_IS_INITIALIZING());
    assert(rupdate.num_rpupds > 0);
    assert(rupdate.num_init_ready_pending > 0);
}

static int sef_cb_init_lu(int type, sef_init_info_t *info)
{
    assert(info->endpoint == RS_PROC_NR);
    
    int r = perform_default_state_transfer(type, info);
    if(r != OK) {
        return r;
    }
    
    r = transfer_rs_control(info);
    if(r != OK) {
        return r;
    }
    
    validate_update_state();
    
    return OK;
}

/*===========================================================================*
*			    sef_cb_init_response			     *
 *===========================================================================*/
int sef_cb_init_response(message *m_ptr)
{
  int r = m_ptr->m_rs_init.result;
  if(r != OK) {
      return r;
  }

  r = do_init_ready(m_ptr);
  return (r == EDONTREPLY) ? OK : r;
}

/*===========================================================================*
*			     sef_cb_lu_response				     *
 *===========================================================================*/
int sef_cb_lu_response(message *m_ptr)
{
  int r = do_upd_ready(m_ptr);
  return (r == EDONTREPLY) ? EGENERIC : r;
}

/*===========================================================================*
 *		            sef_cb_signal_handler                            *
 *===========================================================================*/
static void sef_cb_signal_handler(int signo)
{
    switch(signo) {
        case SIGCHLD:
            do_sigchld();
            break;
        case SIGTERM:
            do_shutdown(NULL);
            break;
    }
}

/*===========================================================================*
 *		            sef_cb_signal_manager                            *
 *===========================================================================*/
static int validate_target(endpoint_t target, int signo, struct rproc **rp)
{
    int target_p;
    
    if (rs_isokendpt(target, &target_p) != OK || rproc_ptr[target_p] == NULL) {
        if (rs_verbose)
            printf("RS: ignoring spurious signal %d for process %d\n", signo, target);
        return OK;
    }
    
    *rp = rproc_ptr[target_p];
    return -1;
}

static int check_process_state(struct rproc *rp, int signo)
{
    if ((rp->r_flags & RS_TERMINATED) && !(rp->r_flags & RS_EXITING)) {
        return EDEADEPT;
    }
    
    if (!(rp->r_flags & RS_ACTIVE) && !(rp->r_flags & RS_EXITING)) {
        if (rs_verbose)
            printf("RS: ignoring signal %d for inactive %s\n", signo, srv_to_string(rp));
        return OK;
    }
    
    return -1;
}

static void log_signal_received(struct rproc *rp, int signo)
{
    if (rs_verbose) {
        printf("RS: %s got %s signal %d\n", srv_to_string(rp),
            SIGS_IS_TERMINATION(signo) ? "termination" : "non-termination", signo);
    }
}

static int handle_termination_signal(struct rproc *rp)
{
    rp->r_flags |= RS_TERMINATED;
    terminate_service(rp);
    rs_idle_period();
    return EDEADEPT;
}

static int deliver_non_termination_signal(struct rproc *rp, int signo)
{
    message m;
    
    if (rp->r_pub->endpoint == VM_PROC_NR) {
        return OK;
    }
    
    m.m_type = SIGS_SIGNAL_RECEIVED;
    m.m_pm_lsys_sigs_signal.num = signo;
    rs_asynsend(rp, &m, 1);
    
    return OK;
}

static int sef_cb_signal_manager(endpoint_t target, int signo)
{
    struct rproc *rp;
    int result;
    
    result = validate_target(target, signo, &rp);
    if (result != -1) {
        return result;
    }
    
    result = check_process_state(rp, signo);
    if (result != -1) {
        return result;
    }
    
    log_signal_received(rp, signo);
    
    if (SIGS_IS_STACKTRACE(signo)) {
        sys_diagctl_stacktrace(target);
    }
    
    if (SIGS_IS_TERMINATION(signo)) {
        return handle_termination_signal(rp);
    }
    
    return deliver_non_termination_signal(rp, signo);
}

/*===========================================================================*
 *                         boot_image_info_lookup                            *
 *===========================================================================*/
static void boot_image_info_lookup(endpoint, image, ip, pp, sp, dp)
endpoint_t endpoint;
struct boot_image *image;
struct boot_image **ip;
struct boot_image_priv **pp;
struct boot_image_sys **sp;
struct boot_image_dev **dp;
{
/* Lookup entries in boot image tables. */
  int i;

  /* When requested, locate the corresponding entry in the boot image table
   * or panic if not found.
   */
  if(ip) {
      for (i=0; i < NR_BOOT_PROCS; i++) {
          if(image[i].endpoint == endpoint) {
              *ip = &image[i];
              break;
          }
      }
      if(i == NR_BOOT_PROCS) {
          panic("boot image table lookup failed");
      }
  }

  /* When requested, locate the corresponding entry in the boot image priv table
   * or panic if not found.
   */
  if(pp) {
      for (i=0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
          if(boot_image_priv_table[i].endpoint == endpoint) {
              *pp = &boot_image_priv_table[i];
              break;
          }
      }
      if(i == NULL_BOOT_NR) {
          panic("boot image priv table lookup failed");
      }
  }

  /* When requested, locate the corresponding entry in the boot image sys table
   * or resort to the default entry if not found.
   */
  if(sp) {
      for (i=0; boot_image_sys_table[i].endpoint != DEFAULT_BOOT_NR; i++) {
          if(boot_image_sys_table[i].endpoint == endpoint) {
              *sp = &boot_image_sys_table[i];
              break;
          }
      }
      if(boot_image_sys_table[i].endpoint == DEFAULT_BOOT_NR) {
          *sp = &boot_image_sys_table[i];         /* accept the default entry */
      }
  }

  /* When requested, locate the corresponding entry in the boot image dev table
   * or resort to the default entry if not found.
   */
  if(dp) {
      for (i=0; boot_image_dev_table[i].endpoint != DEFAULT_BOOT_NR; i++) {
          if(boot_image_dev_table[i].endpoint == endpoint) {
              *dp = &boot_image_dev_table[i];
              break;
          }
      }
      if(boot_image_dev_table[i].endpoint == DEFAULT_BOOT_NR) {
          *dp = &boot_image_dev_table[i];         /* accept the default entry */
      }
  }
}

/*===========================================================================*
 *			      catch_boot_init_ready                          *
 *===========================================================================*/
static void catch_boot_init_ready(endpoint)
endpoint_t endpoint;
{
/* Block and catch an init ready message from the given source. */
  int r;
  int ipc_status;
  message m;
  struct rproc *rp;
  int result;

  /* Receive init ready message. */
  if ((r = sef_receive_status(endpoint, &m, &ipc_status)) != OK) {
      panic("unable to receive init reply: %d", r);
  }
  if(m.m_type != RS_INIT) {
      panic("unexpected reply from service: %d", m.m_source);
  }
  result = m.m_rs_init.result;
  rp = rproc_ptr[_ENDPOINT_P(m.m_source)];

  /* Check result. */
  if(result != OK) {
      panic("unable to complete init for service: %d", m.m_source);
  }

  /* Send a reply to unblock the service, except to VM, which sent the reply
   * asynchronously.  Synchronous replies could lead to deadlocks there.
   */
  if (m.m_source != VM_PROC_NR) {
      m.m_type = OK;
      reply(m.m_source, rp, &m);
  }

  /* Mark the slot as no longer initializing. */
  rp->r_flags &= ~RS_INITIALIZING;
  rp->r_check_tm = 0;
  rp->r_alive_tm = getticks();
}

/*===========================================================================*
 *				get_work                                     *
 *===========================================================================*/
static void get_work(m_ptr, status_ptr)
message *m_ptr;				/* pointer to message */
int *status_ptr;			/* pointer to status */
{
    int r;
    if (OK != (r=sef_receive_status(ANY, m_ptr, status_ptr)))
        panic("sef_receive_status failed: %d", r);
}

