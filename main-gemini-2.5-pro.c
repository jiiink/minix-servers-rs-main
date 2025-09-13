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
                printf("RS: warning: got unexpected notify message from %d\n", m->m_source);
            }
            break;
    }
}

static void handle_request(message *m, int who_e)
{
    int result;

    switch (m->m_type) {
        case RS_UP:         result = do_up(m);          break;
        case RS_DOWN:       result = do_down(m);        break;
        case RS_REFRESH:    result = do_refresh(m);     break;
        case RS_RESTART:    result = do_restart(m);     break;
        case RS_SHUTDOWN:   result = do_shutdown(m);    break;
        case RS_UPDATE:     result = do_update(m);      break;
        case RS_CLONE:      result = do_clone(m);       break;
        case RS_UNCLONE:    result = do_unclone(m);     break;
        case RS_EDIT:       result = do_edit(m);        break;
        case RS_SYSCTL:     result = do_sysctl(m);      break;
        case RS_FI:         result = do_fi(m);          break;
        case RS_GETSYSINFO: result = do_getsysinfo(m);  break;
        case RS_LOOKUP:     result = do_lookup(m);      break;
        case RS_INIT:       result = do_init_ready(m);  break;
        case RS_LU_PREPARE: result = do_upd_ready(m);   break;
        default:
            printf("RS: warning: got unexpected request %d from %d\n", m->m_type, m->m_source);
            result = ENOSYS;
            break;
    }

    if (result != EDONTREPLY) {
        m->m_type = result;
        reply(who_e, NULL, m);
    }
}

int main(void)
{
    sef_local_startup();

    int s;
    if ((s = sys_getmachine(&machine)) != OK) {
        panic("couldn't get machine info: %d", s);
    }

    for (;;) {
        rs_idle_period();

        message m;
        int ipc_status;
        get_work(&m, &ipc_status);

        int who_p;
        const int who_e = m.m_source;
        if (rs_isokendpt(who_e, &who_p) != OK) {
            panic("message from bogus source: %d", who_e);
        }

        if (is_ipc_notify(ipc_status)) {
            handle_notification(&m, who_p);
            continue;
        }

        handle_request(&m, who_e);
    }
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
static void sef_register_callbacks(void)
{
    sef_setcb_init_fresh(sef_cb_init_fresh);
    sef_setcb_init_restart(sef_cb_init_restart);
    sef_setcb_init_lu(sef_cb_init_lu);
    sef_setcb_init_response(sef_cb_init_response);
    sef_setcb_lu_response(sef_cb_lu_response);
    sef_setcb_signal_handler(sef_cb_signal_handler);
    sef_setcb_signal_manager(sef_cb_signal_manager);
}

static void sef_local_startup(void)
{
    sef_register_callbacks();
    sef_startup();
}

/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
static void initialize_globals(void)
{
    int s;

    env_parse("rs_verbose", "d", 0, &rs_verbose, 0, 1);

    s = sys_getinfo(GET_HZ, &system_hz, sizeof(system_hz), 0, 0);
    if (s != OK)
        panic("Cannot get system timer frequency");

    rinit.rproctab_gid = cpf_grant_direct(ANY, (vir_bytes) rprocpub,
        sizeof(rprocpub), CPF_READ);
    if (!GRANT_VALID(rinit.rproctab_gid)) {
        panic("unable to create rprocpub table grant: %d", rinit.rproctab_gid);
    }

    RUPDATE_INIT();
    shutting_down = FALSE;
}

static void get_and_validate_boot_image(struct boot_image image[NR_BOOT_PROCS])
{
    int s;
    if ((s = sys_getimage(image)) != OK) {
        panic("unable to get copy of boot image table: %d", s);
    }

    int nr_image_srvs = 0;
    for (int i = 0; i < NR_BOOT_PROCS; i++) {
        if (!iskerneln(_ENDPOINT_P(image[i].endpoint))) {
            nr_image_srvs++;
        }
    }

    int nr_image_priv_srvs = 0;
    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        if (!iskerneln(_ENDPOINT_P(boot_image_priv_table[i].endpoint))) {
            nr_image_priv_srvs++;
        }
    }

    if (nr_image_srvs != nr_image_priv_srvs) {
        panic("boot image table and boot image priv table mismatch");
    }
}

static void reset_rproc_table(void)
{
    for (struct rproc *rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
        rp->r_flags = 0;
        rp->r_init_err = ERESTART;
        rp->r_pub = &rprocpub[rp - rproc];
        rp->r_pub->in_use = FALSE;
        rp->r_pub->old_endpoint = NONE;
        rp->r_pub->new_endpoint = NONE;
    }
}

static const int all_c[] = { ALL_C, NULL_C };
static const int no_c[] = {  NULL_C };

static void set_privileges(struct rproc *rp, endpoint_t ip_endpoint, const struct boot_image_priv *priv)
{
    int s;
    strcpy(rp->r_pub->label, priv->label);

    rp->r_priv.s_id = static_priv_id(_ENDPOINT_P(priv->endpoint));
    rp->r_priv.s_flags = priv->flags;
    rp->r_priv.s_init_flags = SRV_OR_USR(rp, SRV_I, USR_I);
    rp->r_priv.s_trap_mask= SRV_OR_USR(rp, SRV_T, USR_T);
    rp->r_priv.s_sig_mgr= SRV_OR_USR(rp, SRV_SM, USR_SM);
    rp->r_priv.s_bak_sig_mgr = NONE;

    int ipc_to = SRV_OR_USR(rp, SRV_M, USR_M);
    fill_send_mask(&rp->r_priv.s_ipc_to, ipc_to == ALL_M);

    int *calls = (SRV_OR_USR(rp, SRV_KC, USR_KC) == ALL_C) ? (int *)all_c : (int *)no_c;
    fill_call_mask(calls, NR_SYS_CALLS, rp->r_priv.s_k_call_mask, KERNEL_CALL, TRUE);

    if (priv->endpoint != RS_PROC_NR && priv->endpoint != VM_PROC_NR) {
        if ((s = sys_privctl(ip_endpoint, SYS_PRIV_SET_SYS, &rp->r_priv)) != OK) {
            panic("unable to set privilege structure: %d", s);
        }
    }

    if ((s = sys_getpriv(&rp->r_priv, ip_endpoint)) != OK) {
        panic("unable to synch privilege structure: %d", s);
    }
}

static void set_properties(struct rproc *rp, const struct boot_image *ip,
    const struct boot_image_sys *sys, const struct boot_image_dev *dev)
{
    struct rprocpub *rpub = rp->r_pub;

    rpub->sys_flags = sys->flags;
    rpub->dev_nr = dev->dev_nr;

    strlcpy(rp->r_cmd, ip->proc_name, sizeof(rp->r_cmd));
    rp->r_script[0]= '\0';
    build_cmd_dep(rp);

    strlcpy(rpub->proc_name, ip->proc_name, sizeof(rpub->proc_name));

    int *calls = (SRV_OR_USR(rp, SRV_VC, USR_VC) == ALL_C) ? (int *)all_c : (int *)no_c;
    fill_call_mask(calls, NR_VM_CALLS, rpub->vm_call_mask, VM_RQ_BASE, TRUE);

    rp->r_scheduler = SRV_OR_USR(rp, SRV_SCH, USR_SCH);
    rp->r_priority = SRV_OR_USR(rp, SRV_Q, USR_Q);
    rp->r_quantum = SRV_OR_USR(rp, SRV_QT, USR_QT);

    rpub->endpoint = ip->endpoint;
}

static void set_defaults(struct rproc *rp)
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

static void populate_rproc_table(const struct boot_image image[NR_BOOT_PROCS])
{
    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        const struct boot_image_priv *priv = &boot_image_priv_table[i];
        if (iskerneln(_ENDPOINT_P(priv->endpoint))) {
            continue;
        }

        const struct boot_image *ip;
        const struct boot_image_sys *sys;
        const struct boot_image_dev *dev;
        boot_image_info_lookup(priv->endpoint, image, &ip, NULL, &sys, &dev);

        struct rproc *rp = &rproc[priv - boot_image_priv_table];

        set_privileges(rp, ip->endpoint, priv);
        set_properties(rp, ip, sys, dev);
        set_defaults(rp);

        rp->r_flags = RS_IN_USE | RS_ACTIVE;
        rproc_ptr[_ENDPOINT_P(rp->r_pub->endpoint)] = rp;
        rp->r_pub->in_use = TRUE;
    }
}

static int start_boot_services(void)
{
    int nr_uncaught_init_srvs = 0;
    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        const struct boot_image_priv *priv = &boot_image_priv_table[i];
        if (iskerneln(_ENDPOINT_P(priv->endpoint))) {
            continue;
        }

        struct rproc *rp = &rproc[priv - boot_image_priv_table];
        struct rprocpub *rpub = rp->r_pub;
        int s;

        if (priv->endpoint == RS_PROC_NR || priv->endpoint == VM_PROC_NR) {
            if ((s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags)) != OK) {
                panic("unable to initialize %d: %d", priv->endpoint, s);
            }
            if (priv->endpoint != RS_PROC_NR) {
                nr_uncaught_init_srvs++;
            }
            continue;
        }

        if ((s = sched_init_proc(rp)) != OK) {
            panic("unable to initialize scheduling: %d", s);
        }
        if ((s = sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL)) != OK) {
            panic("unable to initialize privileges: %d", s);
        }

        if (priv->flags & SYS_PROC) {
            if ((s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags)) != OK) {
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

static void wait_for_services_init(int count)
{
    while (count > 0) {
        catch_boot_init_ready(ANY);
        count--;
    }
}

static void finalize_service_pids(void)
{
    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        const struct boot_image_priv *priv = &boot_image_priv_table[i];
        if (iskerneln(_ENDPOINT_P(priv->endpoint))) {
            continue;
        }

        struct rproc *rp = &rproc[priv - boot_image_priv_table];
        rp->r_pid = getnpid(rp->r_pub->endpoint);
        if (rp->r_pid < 0) {
            panic("unable to get pid: %d", rp->r_pid);
        }
    }
}

#if USE_LIVEUPDATE
static void do_rs_update(struct rproc *old_rp, struct rproc *new_rp)
{
    int s;
    if ((s = update_service(&old_rp, &new_rp, RS_SWAP, 0)) != OK) {
        panic("unable to live update RS: %d", s);
    }
    cpf_reload();

    cleanup_service(old_rp);

    if ((s = vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0)) != OK) {
        panic("unable to pin memory for the new RS instance: %d", s);
    }
}

static void yield_to_rs_replica(struct rproc *replica_rp)
{
    int s;
    endpoint_t replica_endpoint = replica_rp->r_pub->endpoint;

    s = sys_privctl(replica_endpoint, SYS_PRIV_SET_SYS, &replica_rp->r_priv);
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

static void perform_rs_live_update(void)
{
    struct rproc *rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    struct rproc *replica_rp;
    int s;

    if ((s = clone_slot(rp, &replica_rp)) != OK) {
        panic("unable to clone current RS instance: %d", s);
    }

    pid_t pid = srv_fork(0, 0);
    if (pid < 0) {
        panic("unable to fork a new RS instance: %d", pid);
    }

    if (pid == 0) {
        /* New RS instance. */
        do_rs_update(rp, replica_rp);
    } else {
        /* Old RS instance. */
        endpoint_t replica_endpoint;
        if ((s = getprocnr(pid, &replica_endpoint)) != 0) {
            panic("unable to get replica endpoint: %d", s);
        }
        replica_rp->r_pid = pid;
        replica_rp->r_pub->endpoint = replica_endpoint;

        yield_to_rs_replica(replica_rp);
    }
}
#endif

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
    initialize_globals();

    struct boot_image image[NR_BOOT_PROCS];
    get_and_validate_boot_image(image);

    reset_rproc_table();
    populate_rproc_table(image);

    int nr_uncaught_init_srvs = start_boot_services();
    wait_for_services_init(nr_uncaught_init_srvs);

    finalize_service_pids();

    int s;
    if ((s = sys_setalarm(RS_DELTA_T, 0)) != OK) {
        panic("couldn't set alarm: %d", s);
    }

#if USE_LIVEUPDATE
    perform_rs_live_update();
#endif

    return OK;
}

/*===========================================================================*
 *		            sef_cb_init_restart                              *
 *===========================================================================*/
static int sef_cb_init_restart(int type, sef_init_info_t *info)
{
    int r;
    struct rproc *old_rs_rp;
    struct rproc *new_rs_rp;

    assert(info->endpoint == RS_PROC_NR);

    r = SEF_CB_INIT_RESTART_STATEFUL(type, info);
    if (r != OK) {
        printf("SEF_CB_INIT_RESTART_STATEFUL failed: %d\n", r);
        return r;
    }

    old_rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    new_rs_rp = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];
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
    assert(info->endpoint == RS_PROC_NR);

    sef_setcb_init_restart(SEF_CB_INIT_RESTART_STATEFUL);

    int r = SEF_CB_INIT_LU_DEFAULT(type, info);
    if (r != OK) {
        printf("SEF_CB_INIT_LU_DEFAULT failed: %d\n", r);
        return r;
    }

    struct rproc *old_rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    struct rproc *new_rs_rp = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];

    if (rs_verbose) {
        printf("RS: %s is the new RS after live update\n",
            srv_to_string(new_rs_rp));
    }

    r = update_service(&old_rs_rp, &new_rs_rp, RS_DONTSWAP, 0);
    if (r != OK) {
        printf("update_service failed: %d\n", r);
        return r;
    }

    assert(RUPDATE_IS_UPDATING());
    assert(RUPDATE_IS_INITIALIZING());
    assert(rupdate.num_rpupds > 0);
    assert(rupdate.num_init_ready_pending > 0);

    return OK;
}

/*===========================================================================*
*			    sef_cb_init_response			     *
 *===========================================================================*/
int sef_cb_init_response(message *m_ptr)
{
    int r = m_ptr->m_rs_init.result;
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

    const int r = do_upd_ready(m_ptr);

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
    switch (signo) {
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
    if (rs_isokendpt(target, &target_p) != OK || rproc_ptr[target_p] == NULL) {
        if (rs_verbose) {
            printf("RS: ignoring spurious signal %d for process %d\n",
                signo, target);
        }
        return OK;
    }

    struct rproc *rp = rproc_ptr[target_p];

    if (!(rp->r_flags & RS_EXITING)) {
        if (rp->r_flags & RS_TERMINATED) {
            return EDEADEPT;
        }
        if (!(rp->r_flags & RS_ACTIVE)) {
            if (rs_verbose) {
                printf("RS: ignoring signal %d for inactive %s\n",
                    signo, srv_to_string(rp));
            }
            return OK;
        }
    }

    if (rs_verbose) {
        printf("RS: %s got %s signal %d\n", srv_to_string(rp),
            SIGS_IS_TERMINATION(signo) ? "termination" : "non-termination",
            signo);
    }

    if (SIGS_IS_STACKTRACE(signo)) {
        sys_diagctl_stacktrace(target);
    }

    if (SIGS_IS_TERMINATION(signo)) {
        rp->r_flags |= RS_TERMINATED;
        terminate_service(rp);
        rs_idle_period();
        return EDEADEPT;
    }

    if (rp->r_pub->endpoint == VM_PROC_NR) {
        return OK;
    }

    message m;
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

