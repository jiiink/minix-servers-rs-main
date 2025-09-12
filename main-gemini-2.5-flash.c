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
static void handle_notification(message *m, int who_p);
static void handle_request(message *m, int who_e);
static void process_work_message(message *m, int ipc_status);

int main(void)
{
  int s;

  sef_local_startup();
  
  if (OK != (s = sys_getmachine(&machine))) {
    panic("couldn't get machine info: %d", s);
  }

  while (TRUE) {              
    message m;
    int ipc_status;

    rs_idle_period();

    get_work(&m, &ipc_status);

    process_work_message(&m, ipc_status);
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
        printf("RS: warning: got unexpected notify message from %d\n", m->m_source);
      }
      break;
  }
}

static void handle_request(message *m, int who_e)
{
  int result;
  int call_nr = m->m_type;

  switch(call_nr) {
    case RS_UP:		result = do_up(m);		break;
    case RS_DOWN: 	result = do_down(m); 		break;
    case RS_REFRESH: 	result = do_refresh(m); 	break;
    case RS_RESTART: 	result = do_restart(m); 	break;
    case RS_SHUTDOWN: 	result = do_shutdown(m); 	break;
    case RS_UPDATE: 	result = do_update(m); 	break;
    case RS_CLONE: 	result = do_clone(m); 		break;
    case RS_UNCLONE: 	result = do_unclone(m);	break;
    case RS_EDIT: 	result = do_edit(m); 		break;
    case RS_SYSCTL:	result = do_sysctl(m);		break;
    case RS_FI:	result = do_fi(m);		break;
    case RS_GETSYSINFO:  result = do_getsysinfo(m);     break;
    case RS_LOOKUP:	result = do_lookup(m);		break;
    case RS_INIT: 	result = do_init_ready(m); 	break;
    case RS_LU_PREPARE: result = do_upd_ready(m); 	break;
    default: 
      printf("RS: warning: got unexpected request %d from %d\n",
          m->m_type, m->m_source);
      result = ENOSYS;
      break;
  }

  if (result != EDONTREPLY) {
    m->m_type = result;
    reply(who_e, NULL, m);
  }
}

static void process_work_message(message *m, int ipc_status)
{
  int who_e = m->m_source;
  int who_p;

  if (rs_isokendpt(who_e, &who_p) != OK) {
    panic("message from bogus source: %d", who_e);
  }

  if (is_ipc_notify(ipc_status)) {
    handle_notification(m, who_p);
  } else {
    handle_request(m, who_e);
  }
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
static void sef_local_startup()
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
static int handle_critical_error(const char *msg, int code) {
    panic(msg, code);
    return code;
}

static int rs_initialize_system_globals(void) {
    int s;
    env_parse("rs_verbose", "d", 0, &rs_verbose, 0, 1);

    if ((s = sys_getinfo(GET_HZ, &system_hz, sizeof(system_hz), 0, 0)) != OK) {
        return handle_critical_error("Cannot get system timer frequency: %d", s);
    }

    rinit.rproctab_gid = cpf_grant_direct(ANY, (vir_bytes)rprocpub, sizeof(rprocpub), CPF_READ);
    if (!GRANT_VALID(rinit.rproctab_gid)) {
        return handle_critical_error("unable to create rprocpub table grant: %d", rinit.rproctab_gid);
    }

    RUPDATE_INIT();
    shutting_down = FALSE;
    return OK;
}

static int rs_load_and_validate_boot_images(struct boot_image *image, int *nr_image_srvs_out, int *nr_image_priv_srvs_out) {
    int s, i;
    struct boot_image *ip;
    const struct boot_image_priv *boot_image_priv;

    if ((s = sys_getimage(image)) != OK) {
        return handle_critical_error("unable to get copy of boot image table: %d", s);
    }

    *nr_image_srvs_out = 0;
    for (i = 0; i < NR_BOOT_PROCS; i++) {
        ip = &image[i];
        if (iskerneln(_ENDPOINT_P(ip->endpoint))) {
            continue;
        }
        (*nr_image_srvs_out)++;
    }

    *nr_image_priv_srvs_out = 0;
    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            continue;
        }
        (*nr_image_priv_srvs_out)++;
    }

    if (*nr_image_srvs_out != *nr_image_priv_srvs_out) {
        return handle_critical_error("boot image table and boot image priv table mismatch: %d vs %d",
                                     *nr_image_srvs_out, *nr_image_priv_srvs_out);
    }
    return OK;
}

static void rs_reset_rproc_table(void) {
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

static int rs_setup_service_privileges_and_properties(int priv_idx, const struct boot_image *image_table) {
    int s;
    const struct boot_image_priv *boot_image_priv = &boot_image_priv_table[priv_idx];
    struct boot_image *ip;
    struct boot_image_sys *boot_image_sys;
    struct boot_image_dev *boot_image_dev;
    struct rproc *rp = &rproc[priv_idx];
    struct rprocpub *rpub = rp->r_pub;
    int *calls;
    int all_c[] = { ALL_C, NULL_C };
    int no_c[] = {  NULL_C };

    boot_image_info_lookup(boot_image_priv->endpoint, image_table, &ip, NULL, &boot_image_sys, &boot_image_dev);

    strlcpy(rpub->label, boot_image_priv->label, sizeof(rpub->label));
    rp->r_priv.s_id = static_priv_id(_ENDPOINT_P(boot_image_priv->endpoint));
    rp->r_priv.s_flags = boot_image_priv->flags;
    rp->r_priv.s_init_flags = SRV_OR_USR(rp, SRV_I, USR_I);
    rp->r_priv.s_trap_mask = SRV_OR_USR(rp, SRV_T, USR_T);
    fill_send_mask(&rp->r_priv.s_ipc_to, SRV_OR_USR(rp, SRV_M, USR_M) == ALL_M);
    rp->r_priv.s_sig_mgr = SRV_OR_USR(rp, SRV_SM, USR_SM);
    rp->r_priv.s_bak_sig_mgr = NONE;

    calls = SRV_OR_USR(rp, SRV_KC, USR_KC) == ALL_C ? all_c : no_c;
    fill_call_mask(calls, NR_SYS_CALLS, rp->r_priv.s_k_call_mask, KERNEL_CALL, TRUE);

    if (boot_image_priv->endpoint != RS_PROC_NR && boot_image_priv->endpoint != VM_PROC_NR) {
        if ((s = sys_privctl(ip->endpoint, SYS_PRIV_SET_SYS, &(rp->r_priv))) != OK) {
            return handle_critical_error("unable to set privilege structure for %d: %d", ip->endpoint, s);
        }
    }
    if ((s = sys_getpriv(&(rp->r_priv), ip->endpoint)) != OK) {
        return handle_critical_error("unable to synch privilege structure for %d: %d", ip->endpoint, s);
    }

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

    return OK;
}

static int rs_activate_service(int priv_idx, int *nr_uncaught_init_srvs_out) {
    int s;
    const struct boot_image_priv *boot_image_priv = &boot_image_priv_table[priv_idx];
    struct rproc *rp = &rproc[priv_idx];
    struct rprocpub *rpub = rp->r_pub;

    if (boot_image_priv->endpoint == RS_PROC_NR || boot_image_priv->endpoint == VM_PROC_NR) {
        if ((s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags)) != OK) {
            return handle_critical_error("unable to initialize %d: %d", boot_image_priv->endpoint, s);
        }
        if (boot_image_priv->endpoint != RS_PROC_NR) {
            (*nr_uncaught_init_srvs_out)++;
        }
        return OK;
    }

    if ((s = sched_init_proc(rp)) != OK) {
        return handle_critical_error("unable to initialize scheduling for %d: %d", rpub->endpoint, s);
    }
    if ((s = sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL)) != OK) {
        return handle_critical_error("unable to initialize privileges for %d: %d", rpub->endpoint, s);
    }

    if (boot_image_priv->flags & SYS_PROC) {
        if ((s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags)) != OK) {
            return handle_critical_error("unable to initialize service %d: %d", rpub->endpoint, s);
        }
        if (rpub->sys_flags & SF_SYNCH_BOOT) {
            catch_boot_init_ready(rpub->endpoint);
        } else {
            (*nr_uncaught_init_srvs_out)++;
        }
    }
    return OK;
}

static void rs_wait_for_all_service_inits(int *nr_uncaught_init_srvs_out) {
    while (*nr_uncaught_init_srvs_out > 0) {
        catch_boot_init_ready(ANY);
        (*nr_uncaught_init_srvs_out)--;
    }
}

static int rs_get_service_pids(int priv_idx) {
    const struct boot_image_priv *boot_image_priv = &boot_image_priv_table[priv_idx];
    struct rproc *rp = &rproc[priv_idx];

    rp->r_pid = getnpid(rp->r_pub->endpoint);
    if (rp->r_pid < 0) {
        return handle_critical_error("unable to get pid for %d: %d", boot_image_priv->endpoint, rp->r_pid);
    }
    return OK;
}

#if USE_LIVEUPDATE
static int rs_setup_live_update(void) {
    int s;
    struct rproc *rp, *replica_rp;
    int pid, replica_pid;
    endpoint_t replica_endpoint;

    rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    if ((s = clone_slot(rp, &replica_rp)) != OK) {
        return handle_critical_error("unable to clone current RS instance: %d", s);
    }

    pid = srv_fork(0, 0);
    if (pid < 0) {
        return handle_critical_error("unable to fork a new RS instance: %d", pid);
    }

    replica_pid = pid ? pid : getpid();
    if ((s = getprocnr(replica_pid, &replica_endpoint)) != 0) {
        return handle_critical_error("unable to get replica endpoint: %d", s);
    }
    replica_rp->r_pid = replica_pid;
    replica_rp->r_pub->endpoint = replica_endpoint;

    if (pid == 0) {
        s = update_service(&rp, &replica_rp, RS_SWAP, 0);
        if (s != OK) {
            return handle_critical_error("unable to live update RS: %d", s);
        }
        cpf_reload();

        cleanup_service(rp);

        if ((s = vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0)) != OK) {
            return handle_critical_error("unable to pin memory for the new RS instance: %d", s);
        }
    } else {
        s = sys_privctl(replica_endpoint, SYS_PRIV_SET_SYS, &(replica_rp->r_priv));
        if (s != OK) {
            return handle_critical_error("unable to set privileges for the new RS instance: %d", s);
        }
        if ((s = sched_init_proc(replica_rp)) != OK) {
            return handle_critical_error("unable to initialize RS replica scheduling: %d", s);
        }
        s = sys_privctl(replica_endpoint, SYS_PRIV_YIELD, NULL);
        if (s != OK) {
            return handle_critical_error("unable to yield control to the new RS instance: %d", s);
        }
        NOT_REACHABLE;
    }
    return OK;
}
#endif

static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
    int s;
    struct boot_image image[NR_BOOT_PROCS];
    int nr_image_srvs = 0;
    int nr_image_priv_srvs = 0;
    int nr_uncaught_init_srvs = 0;
    int i;
    const struct boot_image_priv *boot_image_priv;

    (void)type;
    (void)info;

    if (rs_initialize_system_globals() != OK) {
        return EGENERIC;
    }

    if (rs_load_and_validate_boot_images(image, &nr_image_srvs, &nr_image_priv_srvs) != OK) {
        return EGENERIC;
    }

    rs_reset_rproc_table();

    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            continue;
        }
        if (rs_setup_service_privileges_and_properties(i, image) != OK) {
            return EGENERIC;
        }
    }

    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            continue;
        }
        if (rs_activate_service(i, &nr_uncaught_init_srvs) != OK) {
            return EGENERIC;
        }
    }

    rs_wait_for_all_service_inits(&nr_uncaught_init_srvs);

    for (i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint))) {
            continue;
        }
        if (rs_get_service_pids(i) != OK) {
            return EGENERIC;
        }
    }

    if (OK != (s = sys_setalarm(RS_DELTA_T, 0))) {
        return handle_critical_error("couldn't set alarm: %d", s);
    }

#if USE_LIVEUPDATE
    if (rs_setup_live_update() != OK) {
        return EGENERIC;
    }
#endif

    return OK;
}

/*===========================================================================*
 *		            sef_cb_init_restart                              *
 *===========================================================================*/
static int sef_cb_init_restart(int type, sef_init_info_t *info)
{
  int r;
  struct rproc *current_rs_rproc;
  struct rproc *incoming_rs_rproc;

  assert(info->endpoint == RS_PROC_NR);

  r = SEF_CB_INIT_RESTART_STATEFUL(type, info);
  if (r != OK) {
    printf("SEF_CB_INIT_RESTART_STATEFUL failed: %d\n", r);
    return r;
  }

  current_rs_rproc = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
  incoming_rs_rproc = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];

  if (rs_verbose) {
    printf("RS: %s is the new RS after restart\n", srv_to_string(incoming_rs_rproc));
  }

  if (SRV_IS_UPDATING(current_rs_rproc)) {
    end_update(ERESTART, RS_REPLY);
  }

  r = update_service(&current_rs_rproc, &incoming_rs_rproc, RS_DONTSWAP, 0);
  if (r != OK) {
    printf("update_service failed: %d\n", r);
    return r;
  }

  r = init_service(incoming_rs_rproc, SEF_INIT_RESTART, 0);
  if (r != OK) {
    printf("init_service failed: %d\n", r);
    return r;
  }

  if (OK != (r = sys_setalarm(RS_DELTA_T, 0))) {
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

  /* Use specific negative integers for custom error codes if not defined elsewhere */
#ifndef E_INVALID_ENDPOINT
#define E_INVALID_ENDPOINT -101
#endif
#ifndef E_LIVEUPDATE_STATE_INCONSISTENT
#define E_LIVEUPDATE_STATE_INCONSISTENT -102
#endif

  if (info->endpoint != RS_PROC_NR) {
      printf("SEF_CB_INIT_LU: Invalid endpoint in info. Expected %d, got %d.\n", RS_PROC_NR, info->endpoint);
      return E_INVALID_ENDPOINT;
  }

  sef_setcb_init_restart(SEF_CB_INIT_RESTART_STATEFUL);
  r = SEF_CB_INIT_LU_DEFAULT(type, info);
  if(r != OK) {
      printf("SEF_CB_INIT_LU_DEFAULT failed: %d\n", r);
      return r;
  }

  old_rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
  new_rs_rp = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];
  if(rs_verbose) {
      printf("RS: %s is the new RS after live update\n",
          srv_to_string(new_rs_rp));
  }

  r = update_service(&old_rs_rp, &new_rs_rp, RS_DONTSWAP, 0);
  if(r != OK) {
      printf("update_service failed: %d\n", r);
      return r;
  }

  if (!RUPDATE_IS_UPDATING()) {
      printf("SEF_CB_INIT_LU: RUPDATE_IS_UPDATING check failed.\n");
      return E_LIVEUPDATE_STATE_INCONSISTENT;
  }
  if (!RUPDATE_IS_INITIALIZING()) {
      printf("SEF_CB_INIT_LU: RUPDATE_IS_INITIALIZING check failed.\n");
      return E_LIVEUPDATE_STATE_INCONSISTENT;
  }
  if (!(rupdate.num_rpupds > 0)) {
      printf("SEF_CB_INIT_LU: rupdate.num_rpupds is not greater than 0.\n");
      return E_LIVEUPDATE_STATE_INCONSISTENT;
  }
  if (!(rupdate.num_init_ready_pending > 0)) {
      printf("SEF_CB_INIT_LU: rupdate.num_init_ready_pending is not greater than 0.\n");
      return E_LIVEUPDATE_STATE_INCONSISTENT;
  }

  return OK;
}

/*===========================================================================*
*			    sef_cb_init_response			     *
 *===========================================================================*/
int sef_cb_init_response(message *m_ptr)
{
  if (m_ptr == NULL) {
    return -1; /* Or an appropriate application-specific error code for invalid argument */
  }

  int result = m_ptr->m_rs_init.result;

  if (result != OK) {
    return result;
  }

  result = do_init_ready(m_ptr);

  if (result == EDONTREPLY) {
    result = OK;
  }

  return result;
}

/*===========================================================================*
*			     sef_cb_lu_response				     *
 *===========================================================================*/
int sef_cb_lu_response(message *m_ptr)
{
  int result = do_upd_ready(m_ptr);
  return (result == EDONTREPLY) ? EGENERIC : result;
}

/*===========================================================================*
 *		            sef_cb_signal_handler                            *
 *===========================================================================*/
#include <signal.h>

extern volatile sig_atomic_t g_sigchld_pending;
extern volatile sig_atomic_t g_sigterm_pending;

static void sef_cb_signal_handler(int signo)
{
    switch(signo) {
        case SIGCHLD:
            g_sigchld_pending = 1;
            break;
        case SIGTERM:
            g_sigterm_pending = 1;
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
  _Bool is_termination_signal;

  if (rs_isokendpt(target, &target_p) != OK || rproc_ptr[target_p] == NULL) {
      if (rs_verbose) {
          printf("RS: ignoring spurious signal %d for process %d\n", signo, target);
      }
      return OK;
  }
  rp = rproc_ptr[target_p];

  if ((rp->r_flags & RS_TERMINATED) && !(rp->r_flags & RS_EXITING)) {
      return EDEADEPT;
  }

  if (!(rp->r_flags & RS_ACTIVE) && !(rp->r_flags & RS_EXITING)) {
      if (rs_verbose) {
          printf("RS: ignoring signal %d for inactive %s\n", signo, srv_to_string(rp));
      }
      return OK;
  }

  is_termination_signal = SIGS_IS_TERMINATION(signo);

  if (rs_verbose) {
      printf("RS: %s got %s signal %d\n", srv_to_string(rp),
             is_termination_signal ? "termination" : "non-termination", signo);
  }

  if (SIGS_IS_STACKTRACE(signo)) {
       sys_diagctl_stacktrace(target);
  }

  if (is_termination_signal) {
      rp->r_flags |= RS_TERMINATED;
      terminate_service(rp);
      rs_idle_period();
      return EDEADEPT;
  }

  if (rp->r_pub->endpoint == VM_PROC_NR) {
      return OK;
  }

  {
    message m;
    m.m_type = SIGS_SIGNAL_RECEIVED;
    m.m_pm_lsys_sigs_signal.num = signo;
    rs_asynsend(rp, &m, 1);
  }

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

