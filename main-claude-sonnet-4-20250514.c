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
int main(void)
{
    message m;
    int ipc_status;
    int call_nr, who_e, who_p;
    int result;
    int s;

    sef_local_startup();
    
    s = sys_getmachine(&machine);
    if (s != OK) {
        panic("couldn't get machine info: %d", s);
    }

    while (TRUE) {
        rs_idle_period();
        get_work(&m, &ipc_status);
        
        who_e = m.m_source;
        if (rs_isokendpt(who_e, &who_p) != OK) {
            panic("message from bogus source: %d", who_e);
        }

        call_nr = m.m_type;

        if (is_ipc_notify(ipc_status)) {
            handle_notification(&m, who_p);
            continue;
        }

        result = handle_request(&m, call_nr);

        if (result != EDONTREPLY) {
            m.m_type = result;
            reply(who_e, NULL, &m);
        }
    }
}

static void handle_notification(message *m, int who_p)
{
    switch (who_p) {
    case CLOCK:
        do_period(m);
        break;
    default:
        if (rproc_ptr[who_p] != NULL) {
            rproc_ptr[who_p]->r_alive_tm = m->m_notify.timestamp;
        } else {
            printf("RS: warning: got unexpected notify message from %d\n",
                m->m_source);
        }
        break;
    }
}

static int handle_request(message *m, int call_nr)
{
    switch(call_nr) {
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
        printf("RS: warning: got unexpected request %d from %d\n",
            m->m_type, m->m_source);
        return ENOSYS;
    }
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
static void sef_local_startup(void)
{
  sef_setcb_init_fresh(sef_cb_init_fresh);
  sef_setcb_init_restart(sef_cb_init_restart);
  sef_setcb_init_lu(sef_cb_init_lu);

  sef_setcb_init_response(sef_cb_init_response);
  sef_setcb_lu_response(sef_cb_lu_response);

  sef_setcb_signal_handler(sef_cb_signal_handler);
  sef_setcb_signal_manager(sef_cb_signal_manager);

  sef_startup();
}

/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
    struct boot_image *ip;
    int s, i;
    int nr_image_srvs, nr_image_priv_srvs, nr_uncaught_init_srvs;
    struct rproc *rp;
    struct rproc *replica_rp;
    struct rprocpub *rpub;
    struct boot_image image[NR_BOOT_PROCS];
    struct boot_image_priv *boot_image_priv;
    struct boot_image_sys *boot_image_sys;
    struct boot_image_dev *boot_image_dev;
    int pid, replica_pid;
    endpoint_t replica_endpoint;
    int ipc_to;
    int *calls;
    int all_c[] = { ALL_C, NULL_C };
    int no_c[] = { NULL_C };

    env_parse("rs_verbose", "d", 0, &rs_verbose, 0, 1);

    s = sys_getinfo(GET_HZ, &system_hz, sizeof(system_hz), 0, 0);
    if (s != OK) {
        panic("Cannot get system timer frequency\n");
    }

    rinit.rproctab_gid = cpf_grant_direct(ANY, (vir_bytes) rprocpub,
        sizeof(rprocpub), CPF_READ);
    if (!GRANT_VALID(rinit.rproctab_gid)) {
        panic("unable to create rprocpub table grant: %d", rinit.rproctab_gid);
    }

    RUPDATE_INIT();
    shutting_down = FALSE;

    s = sys_getimage(image);
    if (s != OK) {
        panic("unable to get copy of boot image table: %d", s);
    }

    nr_image_srvs = count_image_services(image);
    nr_image_priv_srvs = count_priv_services();

    if (nr_image_srvs != nr_image_priv_srvs) {
        panic("boot image table and boot image priv table mismatch");
    }

    reset_rproc_table();
    initialize_system_services();
    
    nr_uncaught_init_srvs = allow_services_to_run();
    
    while (nr_uncaught_init_srvs > 0) {
        catch_boot_init_ready(ANY);
        nr_uncaught_init_srvs--;
    }

    complete_service_initialization();

    s = sys_setalarm(RS_DELTA_T, 0);
    if (s != OK) {
        panic("couldn't set alarm: %d", s);
    }

#if USE_LIVEUPDATE
    rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    s = clone_slot(rp, &replica_rp);
    if (s != OK) {
        panic("unable to clone current RS instance: %d", s);
    }

    pid = srv_fork(0, 0);
    if (pid < 0) {
        panic("unable to fork a new RS instance: %d", pid);
    }
    
    replica_pid = (pid != 0) ? pid : getpid();
    s = getprocnr(replica_pid, &replica_endpoint);
    if (s != 0) {
        panic("unable to get replica endpoint: %d", s);
    }
    
    replica_rp->r_pid = replica_pid;
    replica_rp->r_pub->endpoint = replica_endpoint;

    if (pid == 0) {
        handle_new_rs_instance(rp, replica_rp);
    } else {
        handle_old_rs_instance(replica_rp, replica_endpoint);
    }
#endif

    return OK;
}

static int count_image_services(struct boot_image *image)
{
    int count = 0;
    int i;
    struct boot_image *ip;

    for (i = 0; i < NR_BOOT_PROCS; i++) {
        ip = &image[i];
        if (!iskerneln(_ENDPOINT_P(ip->endpoint))) {
            count++;
        }
    }
    return count;
}

static int count_priv_services(void)
{
    int count = 0;
    int i;
    struct boot_image_priv *boot_image_priv;

    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (!iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            count++;
        }
    }
    return count;
}

static void reset_rproc_table(void)
{
    struct rproc *rp;

    for (rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
        rp->r_flags = 0;
        rp->r_init_err = ERESTART;
        rp->r_pub = &rprocpub[rp - rproc];
        rp->r_pub->in_use = FALSE;
        rp->r_pub->old_endpoint = NONE;
        rp->r_pub->new_endpoint = NONE;
    }
}

static void initialize_system_services(void)
{
    int i, s;
    struct boot_image_priv *boot_image_priv;
    struct boot_image *ip;
    struct boot_image_sys *boot_image_sys;
    struct boot_image_dev *boot_image_dev;
    struct rproc *rp;
    struct rprocpub *rpub;
    int ipc_to;
    int *calls;
    int all_c[] = { ALL_C, NULL_C };
    int no_c[] = { NULL_C };

    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];

        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            continue;
        }

        boot_image_info_lookup(boot_image_priv->endpoint, image,
            &ip, NULL, &boot_image_sys, &boot_image_dev);
        rp = &rproc[boot_image_priv - boot_image_priv_table];
        rpub = rp->r_pub;

        setup_service_privileges(rp, rpub, boot_image_priv, ip, all_c, no_c);
        setup_service_properties(rp, rpub, boot_image_sys, boot_image_dev, ip, all_c, no_c);
        initialize_service_defaults(rp, rpub, ip);

        rp->r_flags = RS_IN_USE | RS_ACTIVE;
        rproc_ptr[_ENDPOINT_P(rpub->endpoint)] = rp;
        rpub->in_use = TRUE;
    }
}

static void setup_service_privileges(struct rproc *rp, struct rprocpub *rpub,
    struct boot_image_priv *boot_image_priv, struct boot_image *ip,
    int *all_c, int *no_c)
{
    int s, ipc_to;
    int *calls;

    strcpy(rpub->label, boot_image_priv->label);
    rp->r_priv.s_id = static_priv_id(_ENDPOINT_P(boot_image_priv->endpoint));
    rp->r_priv.s_flags = boot_image_priv->flags;
    rp->r_priv.s_init_flags = SRV_OR_USR(rp, SRV_I, USR_I);
    rp->r_priv.s_trap_mask = SRV_OR_USR(rp, SRV_T, USR_T);
    
    ipc_to = SRV_OR_USR(rp, SRV_M, USR_M);
    fill_send_mask(&rp->r_priv.s_ipc_to, ipc_to == ALL_M);
    rp->r_priv.s_sig_mgr = SRV_OR_USR(rp, SRV_SM, USR_SM);
    rp->r_priv.s_bak_sig_mgr = NONE;

    calls = (SRV_OR_USR(rp, SRV_KC, USR_KC) == ALL_C) ? all_c : no_c;
    fill_call_mask(calls, NR_SYS_CALLS, rp->r_priv.s_k_call_mask, KERNEL_CALL, TRUE);

    if (boot_image_priv->endpoint != RS_PROC_NR && 
        boot_image_priv->endpoint != VM_PROC_NR) {
        s = sys_privctl(ip->endpoint, SYS_PRIV_SET_SYS, &(rp->r_priv));
        if (s != OK) {
            panic("unable to set privilege structure: %d", s);
        }
    }

    s = sys_getpriv(&(rp->r_priv), ip->endpoint);
    if (s != OK) {
        panic("unable to synch privilege structure: %d", s);
    }
}

static void setup_service_properties(struct rproc *rp, struct rprocpub *rpub,
    struct boot_image_sys *boot_image_sys, struct boot_image_dev *boot_image_dev,
    struct boot_image *ip, int *all_c, int *no_c)
{
    int *calls;

    rpub->sys_flags = boot_image_sys->flags;
    rpub->dev_nr = boot_image_dev->dev_nr;

    strlcpy(rp->r_cmd, ip->proc_name, sizeof(rp->r_cmd));
    rp->r_script[0] = '\0';
    build_cmd_dep(rp);
    strlcpy(rpub->proc_name, ip->proc_name, sizeof(rpub->proc_name));

    calls = (SRV_OR_USR(rp, SRV_VC, USR_VC) == ALL_C) ? all_c : no_c;
    fill_call_mask(calls, NR_VM_CALLS, rpub->vm_call_mask, VM_RQ_BASE, TRUE);

    rp->r_scheduler = SRV_OR_USR(rp, SRV_SCH, USR_SCH);
    rp->r_priority = SRV_OR_USR(rp, SRV_Q, USR_Q);
    rp->r_quantum = SRV_OR_USR(rp, SRV_QT, USR_QT);
    rpub->endpoint = ip->endpoint;
}

static void initialize_service_defaults(struct rproc *rp, struct rprocpub *rpub,
    struct boot_image *ip)
{
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
}

static int allow_services_to_run(void)
{
    int i, s;
    int nr_uncaught_init_srvs = 0;
    struct boot_image_priv *boot_image_priv;
    struct rproc *rp;
    struct rprocpub *rpub;

    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];

        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            continue;
        }

        rp = &rproc[boot_image_priv - boot_image_priv_table];
        rpub = rp->r_pub;

        if (boot_image_priv->endpoint == RS_PROC_NR ||
            boot_image_priv->endpoint == VM_PROC_NR) {
            s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags);
            if (s != OK) {
                panic("unable to initialize %d: %d", boot_image_priv->endpoint, s);
            }
            if (boot_image_priv->endpoint != RS_PROC_NR) {
                nr_uncaught_init_srvs++;
            }
            continue;
        }

        s = sched_init_proc(rp);
        if (s != OK) {
            panic("unable to initialize scheduling: %d", s);
        }
        
        s = sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL);
        if (s != OK) {
            panic("unable to initialize privileges: %d", s);
        }

        if (boot_image_priv->flags & SYS_PROC) {
            s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags);
            if (s != OK) {
                panic("unable to initialize service: %d", s);
            }
            if (rpub->sys_flags & SF_SYNCH_BOOT) {
                catch_boot_init_ready(rpub->endpoint);
            } else {
                nr_uncaught_init_srvs++;
            }
        }
    }
    return nr_uncaught_init_srvs;
}

static void complete_service_initialization(void)
{
    int i;
    struct boot_image_priv *boot_image_priv;
    struct rproc *rp;
    struct rprocpub *rpub;

    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];

        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            continue;
        }

        rp = &rproc[boot_image_priv - boot_image_priv_table];
        rpub = rp->r_pub;

        rp->r_pid = getnpid(rpub->endpoint);
        if (rp->r_pid < 0) {
            panic("unable to get pid: %d", rp->r_pid);
        }
    }
}

#if USE_LIVEUPDATE
static void handle_new_rs_instance(struct rproc *rp, struct rproc *replica_rp)
{
    int s;

    s = update_service(&rp, &replica_rp, RS_SWAP, 0);
    if (s != OK) {
        panic("unable to live update RS: %d", s);
    }
    cpf_reload();

    cleanup_service(rp);

    s = vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0);
    if (s != OK) {
        panic("unable to pin memory for the new RS instance: %d", s);
    }
}

static void handle_old_rs_instance(struct rproc *replica_rp, endpoint_t replica_endpoint)
{
    int s;

    s = sys_privctl(replica_endpoint, SYS_PRIV_SET_SYS, &(replica_rp->r_priv));
    if (s != OK) {
        panic("unable to set privileges for the new RS instance: %d", s);
    }
    
    s = sched_init_proc(replica_rp);
    if (s != OK) {
        panic("unable to initialize RS replica scheduling: %d", s);
    }
    
    s = sys_privctl(replica_endpoint, SYS_PRIV_YIELD, NULL);
    if (s != OK) {
        panic("unable to yield control to the new RS instance: %d", s);
    }
    NOT_REACHABLE;
}
#endif

/*===========================================================================*
 *		            sef_cb_init_restart                              *
 *===========================================================================*/
static int sef_cb_init_restart(int type, sef_init_info_t *info)
{
    int r;
    struct rproc *old_rs_rp, *new_rs_rp;

    if (!info || info->endpoint != RS_PROC_NR) {
        return EINVAL;
    }

    r = SEF_CB_INIT_RESTART_STATEFUL(type, info);
    if (r != OK) {
        printf("SEF_CB_INIT_RESTART_STATEFUL failed: %d\n", r);
        return r;
    }

    old_rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    new_rs_rp = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];
    
    if (!old_rs_rp || !new_rs_rp) {
        printf("RS: Invalid process pointers\n");
        return ENOENT;
    }

    if (rs_verbose) {
        printf("RS: %s is the new RS after restart\n", srv_to_string(new_rs_rp));
    }

    if (SRV_IS_UPDATING(old_rs_rp)) {
        end_update(ERESTART, RS_REPLY);
    }

    r = update_service(&old_rs_rp, &new_rs_rp, RS_DONTSWAP, 0);
    if (r != OK) {
        printf("update_service failed: %d\n", r);
        return r;
    }

    r = init_service(new_rs_rp, SEF_INIT_RESTART, 0);
    if (r != OK) {
        printf("init_service failed: %d\n", r);
        return r;
    }

    r = sys_setalarm(RS_DELTA_T, 0);
    if (r != OK) {
        panic("couldn't set alarm: %d", r);
    }

    return OK;
}

/*===========================================================================*
 *		              sef_cb_init_lu                                 *
 *===========================================================================*/
static int sef_cb_init_lu(int type, sef_init_info_t *info)
{
    int r;
    struct rproc *old_rs_rp, *new_rs_rp;

    if (!info || info->endpoint != RS_PROC_NR) {
        return EINVAL;
    }

    sef_setcb_init_restart(SEF_CB_INIT_RESTART_STATEFUL);
    r = SEF_CB_INIT_LU_DEFAULT(type, info);
    if (r != OK) {
        printf("SEF_CB_INIT_LU_DEFAULT failed: %d\n", r);
        return r;
    }

    old_rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    new_rs_rp = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];
    
    if (!old_rs_rp || !new_rs_rp) {
        printf("Invalid rproc pointers\n");
        return EINVAL;
    }

    if (rs_verbose) {
        printf("RS: %s is the new RS after live update\n",
               srv_to_string(new_rs_rp));
    }

    r = update_service(&old_rs_rp, &new_rs_rp, RS_DONTSWAP, 0);
    if (r != OK) {
        printf("update_service failed: %d\n", r);
        return r;
    }

    if (!RUPDATE_IS_UPDATING() || !RUPDATE_IS_INITIALIZING() ||
        rupdate.num_rpupds <= 0 || rupdate.num_init_ready_pending <= 0) {
        printf("Inconsistent update state\n");
        return EINVAL;
    }

    return OK;
}

/*===========================================================================*
*			    sef_cb_init_response			     *
 *===========================================================================*/
int sef_cb_init_response(message *m_ptr)
{
  int r;

  if (!m_ptr) {
    return EINVAL;
  }

  r = m_ptr->m_rs_init.result;
  if (r != OK) {
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
    if (m_ptr == NULL) {
        return EINVAL;
    }

    int r = do_upd_ready(m_ptr);
    
    if (r == EDONTREPLY) {
        return EGENERIC;
    }
    
    return r;
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
      default:
          break;
  }
}

/*===========================================================================*
 *		            sef_cb_signal_manager                            *
 *===========================================================================*/
static int sef_cb_signal_manager(endpoint_t target, int signo)
{
    int target_p;
    struct rproc *rp;
    message m;

    if(rs_isokendpt(target, &target_p) != OK || rproc_ptr[target_p] == NULL) {
        if(rs_verbose) {
            printf("RS: ignoring spurious signal %d for process %d\n", signo, target);
        }
        return OK;
    }
    
    rp = rproc_ptr[target_p];

    if((rp->r_flags & RS_TERMINATED) && !(rp->r_flags & RS_EXITING)) {
        return EDEADEPT;
    }

    if(!(rp->r_flags & RS_ACTIVE) && !(rp->r_flags & RS_EXITING)) {
        if(rs_verbose) {
            printf("RS: ignoring signal %d for inactive %s\n", signo, srv_to_string(rp));
        }
        return OK;
    }

    if(rs_verbose) {
        printf("RS: %s got %s signal %d\n", srv_to_string(rp),
               SIGS_IS_TERMINATION(signo) ? "termination" : "non-termination", signo);
    }

    if(SIGS_IS_STACKTRACE(signo)) {
        sys_diagctl_stacktrace(target);
    }

    if(SIGS_IS_TERMINATION(signo)) {
        rp->r_flags |= RS_TERMINATED;
        terminate_service(rp);
        rs_idle_period();
        return EDEADEPT;
    }

    if(rp->r_pub->endpoint == VM_PROC_NR) {
        return OK;
    }

    m.m_type = SIGS_SIGNAL_RECEIVED;
    m.m_pm_lsys_sigs_signal.num = signo;
    rs_asynsend(rp, &m, 1);

    return OK;
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

