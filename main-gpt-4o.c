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
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

int main(void) {
    message m;
    int ipc_status;
    int call_nr, who_e, who_p;
    int result;
    int s;

    sef_local_startup();

    if ((s = sys_getmachine(&machine)) != OK) {
        fprintf(stderr, "Error: couldn't get machine info: %d\n", s);
        exit(EXIT_FAILURE);
    }

    while (true) {
        rs_idle_period();
        get_work(&m, &ipc_status);

        who_e = m.m_source;
        if (rs_isokendpt(who_e, &who_p) != OK) {
            fprintf(stderr, "Error: message from bogus source: %d\n", who_e);
            continue;
        }

        call_nr = m.m_type;

        if (is_ipc_notify(ipc_status)) {
            if (who_p == CLOCK) {
                do_period(&m);
            } else if (rproc_ptr[who_p] != NULL) {
                rproc_ptr[who_p]->r_alive_tm = m.m_notify.timestamp;
            } else {
                fprintf(stderr, "Warning: unexpected notify message from %d\n", m.m_source);
            }
            continue;
        }

        switch (call_nr) {
            case RS_UP: result = do_up(&m); break;
            case RS_DOWN: result = do_down(&m); break;
            case RS_REFRESH: result = do_refresh(&m); break;
            case RS_RESTART: result = do_restart(&m); break;
            case RS_SHUTDOWN: result = do_shutdown(&m); break;
            case RS_UPDATE: result = do_update(&m); break;
            case RS_CLONE: result = do_clone(&m); break;
            case RS_UNCLONE: result = do_unclone(&m); break;
            case RS_EDIT: result = do_edit(&m); break;
            case RS_SYSCTL: result = do_sysctl(&m); break;
            case RS_FI: result = do_fi(&m); break;
            case RS_GETSYSINFO: result = do_getsysinfo(&m); break;
            case RS_LOOKUP: result = do_lookup(&m); break;
            case RS_INIT: result = do_init_ready(&m); break;
            case RS_LU_PREPARE: result = do_upd_ready(&m); break;
            default:
                fprintf(stderr, "Warning: unexpected request %d from %d\n", m.m_type, m.m_source);
                result = ENOSYS;
        }

        if (result != EDONTREPLY) {
            m.m_type = result;
            if(reply(who_e, NULL, &m) != OK) {
                fprintf(stderr, "Error: failed to send reply to %d\n", who_e);
            }
        }
    }

    return 0;
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
#include <assert.h>

static void register_callbacks() {
    int result = 0;
    
    result |= sef_setcb_init_fresh(sef_cb_init_fresh);
    result |= sef_setcb_init_restart(sef_cb_init_restart);
    result |= sef_setcb_init_lu(sef_cb_init_lu);
    result |= sef_setcb_init_response(sef_cb_init_response);
    result |= sef_setcb_lu_response(sef_cb_lu_response);
    result |= sef_setcb_signal_handler(sef_cb_signal_handler);
    result |= sef_setcb_signal_manager(sef_cb_signal_manager);

    assert(result == 0); // Ensure all callbacks are registered successfully
}

static void sef_local_startup() {
    register_callbacks();
    sef_startup();
}

/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
static int sef_cb_init_fresh(int UNUSED(type), sef_init_info_t *UNUSED(info))
{
    int s;
    int nr_image_srvs = 0, nr_image_priv_srvs = 0, nr_uncaught_init_srvs = 0;
    struct rproc *rp, *replica_rp;
    struct boot_image image[NR_BOOT_PROCS];
    struct boot_image_priv *boot_image_priv;
    int pid, replica_pid;
    endpoint_t replica_endpoint;
    int ipc_to;
    int *calls;
    int all_c[] = { ALL_C, NULL_C };
    int no_c[] = { NULL_C };

    env_parse("rs_verbose", "d", 0, &rs_verbose, 0, 1);

    if ((s = sys_getinfo(GET_HZ, &system_hz, sizeof(system_hz), 0, 0)) != OK)
        panic("Cannot get system timer frequency\n");

    rinit.rproctab_gid = cpf_grant_direct(ANY, (vir_bytes) rprocpub, sizeof(rprocpub), CPF_READ);
    if (!GRANT_VALID(rinit.rproctab_gid))
        panic("unable to create rprocpub table grant");

    RUPDATE_INIT();
    shutting_down = FALSE;

    if ((s = sys_getimage(image)) != OK)
        panic("unable to get copy of boot image table: %d", s);

    for (int i = 0; i < NR_BOOT_PROCS; i++) {
        if (!iskerneln(_ENDPOINT_P(image[i].endpoint)))
            nr_image_srvs++;
    }

    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        if (!iskerneln(_ENDPOINT_P(boot_image_priv_table[i].endpoint)))
            nr_image_priv_srvs++;
    }

    if (nr_image_srvs != nr_image_priv_srvs)
        panic("boot image table and boot image priv table mismatch");

    for (rp = BEG_RPROC_ADDR; rp < END_RPROC_ADDR; rp++) {
        rp->r_flags = 0;
        rp->r_init_err = ERESTART;
        rp->r_pub = &rprocpub[rp - rproc];
        rp->r_pub->in_use = FALSE;
        rp->r_pub->old_endpoint = NONE;
        rp->r_pub->new_endpoint = NONE;
    }

    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint)))
            continue;

        struct boot_image *ip;
        struct boot_image_sys *boot_image_sys;
        struct boot_image_dev *boot_image_dev;
        boot_image_info_lookup(boot_image_priv->endpoint, image, &ip, NULL, &boot_image_sys, &boot_image_dev);

        rp = &rproc[boot_image_priv - boot_image_priv_table];
        struct rprocpub *rpub = rp->r_pub;

        strcpy(rpub->label, boot_image_priv->label);
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

        if (boot_image_priv->endpoint != RS_PROC_NR && boot_image_priv->endpoint != VM_PROC_NR) {
            if ((s = sys_privctl(ip->endpoint, SYS_PRIV_SET_SYS, &rp->r_priv)) != OK)
                panic("unable to set privilege structure: %d", s);
        }

        if ((s = sys_getpriv(&rp->r_priv, ip->endpoint)) != OK)
            panic("unable to sync privilege structure: %d", s);

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
    }

    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint)))
            continue;

        rp = &rproc[boot_image_priv - boot_image_priv_table];
        rpub = rp->r_pub;

        if (boot_image_priv->endpoint == RS_PROC_NR || boot_image_priv->endpoint == VM_PROC_NR) {
            if ((s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags)) != OK)
                panic("unable to initialize %d: %d", boot_image_priv->endpoint, s);
            if (boot_image_priv->endpoint != RS_PROC_NR)
                nr_uncaught_init_srvs++;
            continue;
        }

        if ((s = sched_init_proc(rp)) != OK)
            panic("unable to initialize scheduling: %d", s);
        if ((s = sys_privctl(rpub->endpoint, SYS_PRIV_ALLOW, NULL)) != OK)
            panic("unable to initialize privileges: %d", s);

        if (boot_image_priv->flags & SYS_PROC) {
            if ((s = init_service(rp, SEF_INIT_FRESH, rp->r_priv.s_init_flags)) != OK)
                panic("unable to initialize service: %d", s);
            if (rpub->sys_flags & SF_SYNCH_BOOT)
                catch_boot_init_ready(rpub->endpoint);
            else
                nr_uncaught_init_srvs++;
        }
    }

    while (nr_uncaught_init_srvs--) {
        catch_boot_init_ready(ANY);
    }

    for (int i = 0; boot_image_priv_table[i].endpoint != NULL_BOOT_NR; i++) {
        boot_image_priv = &boot_image_priv_table[i];
        if (iskerneln(_ENDPOINT_P(boot_image_priv->endpoint)))
            continue;

        rp = &rproc[boot_image_priv - boot_image_priv_table];
        rpub = rp->r_pub;

        rp->r_pid = getnpid(rpub->endpoint);
        if (rp->r_pid < 0)
            panic("unable to get pid: %d", rp->r_pid);
    }

    if ((s = sys_setalarm(RS_DELTA_T, 0)) != OK)
        panic("couldn't set alarm: %d", s);

#if USE_LIVEUPDATE
    rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    if ((s = clone_slot(rp, &replica_rp)) != OK)
        panic("unable to clone current RS instance: %d", s);

    pid = srv_fork(0, 0);
    if (pid < 0)
        panic("unable to fork a new RS instance: %d", pid);

    replica_pid = pid ? pid : getpid();
    if ((s = getprocnr(replica_pid, &replica_endpoint)) != 0)
        panic("unable to get replica endpoint: %d", s);
    replica_rp->r_pid = replica_pid;
    replica_rp->r_pub->endpoint = replica_endpoint;

    if (pid == 0) {
        if ((s = update_service(&rp, &replica_rp, RS_SWAP, 0)) != OK)
            panic("unable to live update RS: %d", s);
        
        cpf_reload();
        cleanup_service(rp);

        if ((s = vm_memctl(RS_PROC_NR, VM_RS_MEM_PIN, 0, 0)) != OK)
            panic("unable to pin memory for the new RS instance: %d", s);
    } else {
        if ((s = sys_privctl(replica_endpoint, SYS_PRIV_SET_SYS, &replica_rp->r_priv)) != OK)
            panic("unable to set privileges for the new RS instance: %d", s);
        if ((s = sched_init_proc(replica_rp)) != OK)
            panic("unable to initialize RS replica scheduling: %d", s);
        if ((s = sys_privctl(replica_endpoint, SYS_PRIV_YIELD, NULL)) != OK)
            panic("unable to yield control to the new RS instance: %d", s);

        NOT_REACHABLE;
    }
#endif 

    return OK;
}

/*===========================================================================*
 *		            sef_cb_init_restart                              *
 *===========================================================================*/
int sef_cb_init_restart(int type, sef_init_info_t *info) {
    assert(info->endpoint == RS_PROC_NR);

    int result = SEF_CB_INIT_RESTART_STATEFUL(type, info);
    if (result != OK) {
        fprintf(stderr, "SEF_CB_INIT_RESTART_STATEFUL failed: %d\n", result);
        return result;
    }

    struct rproc *old_rs = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
    struct rproc *new_rs = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];

    if (rs_verbose) {
        printf("RS: %s is the new RS after restart\n", srv_to_string(new_rs));
    }

    if (SRV_IS_UPDATING(old_rs)) {
        end_update(ERESTART, RS_REPLY);
    }

    result = update_service(&old_rs, &new_rs, RS_DONTSWAP, 0);
    if (result != OK) {
        fprintf(stderr, "update_service failed: %d\n", result);
        return result;
    }

    result = init_service(new_rs, SEF_INIT_RESTART, 0);
    if (result != OK) {
        fprintf(stderr, "init_service failed: %d\n", result);
        return result;
    }

    result = sys_setalarm(RS_DELTA_T, 0);
    if (result != OK) {
        panic("couldn't set alarm: %d", result);
    }

    return OK;
}

/*===========================================================================*
 *		              sef_cb_init_lu                                 *
 *===========================================================================*/
#include <assert.h>
#include <stdio.h>

static int update_process(int *old_rs_rp, int *new_rs_rp, int flags, int swap);
static int check_update_conditions();

static int sef_cb_init_lu(int type, sef_init_info_t *info) {
  int r;
  struct rproc *old_rs_rp, *new_rs_rp;

  if (info->endpoint != RS_PROC_NR) {
    fprintf(stderr, "Unexpected endpoint: %d\n", info->endpoint);
    return -1;
  }

  sef_setcb_init_restart(SEF_CB_INIT_RESTART_STATEFUL);
  r = SEF_CB_INIT_LU_DEFAULT(type, info);
  if (r != OK) {
    fprintf(stderr, "SEF_CB_INIT_LU_DEFAULT failed: %d\n", r);
    return r;
  }

  old_rs_rp = rproc_ptr[_ENDPOINT_P(RS_PROC_NR)];
  new_rs_rp = rproc_ptr[_ENDPOINT_P(info->old_endpoint)];

  if (rs_verbose) {
    printf("RS: %s is the new RS after live update\n", srv_to_string(new_rs_rp));
  }

  r = update_process(&old_rs_rp, &new_rs_rp, RS_DONTSWAP, 0);
  if (r != OK) {
    fprintf(stderr, "update_process failed: %d\n", r);
    return r;
  }

  return check_update_conditions();
}

static int update_process(int *old_rs_rp, int *new_rs_rp, int flags, int swap) {
  return update_service(old_rs_rp, new_rs_rp, flags, swap);
}

static int check_update_conditions() {
  if (!RUPDATE_IS_UPDATING() || !RUPDATE_IS_INITIALIZING() || rupdate.num_rpupds <= 0 || rupdate.num_init_ready_pending <= 0) {
    fprintf(stderr, "Update conditions not met\n");
    return -1;
  }
  return OK;
}

/*===========================================================================*
*			    sef_cb_init_response			     *
 *===========================================================================*/
int sef_cb_init_response(message *m_ptr)
{
  int result = m_ptr->m_rs_init.result;
  
  if (result != OK) {
      return result;
  }

  int init_status = do_init_ready(m_ptr);

  return (init_status == EDONTREPLY) ? OK : init_status;
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

static void handle_known_signal(int signo) {
    if (signo == SIGCHLD) {
        do_sigchld();
    } else if (signo == SIGTERM) {
        do_shutdown(NULL);
    }
}

static void sef_cb_signal_handler(int signo) {
    handle_known_signal(signo);
}

/*===========================================================================*
 *		            sef_cb_signal_manager                            *
 *===========================================================================*/
static int sef_cb_signal_manager(endpoint_t target, int signo) {
    int target_p;
    struct rproc *rp;
    message m;

    if (rs_isokendpt(target, &target_p) != OK || (rp = rproc_ptr[target_p]) == NULL) {
        if (rs_verbose) {
            printf("RS: ignoring spurious signal %d for process %d\n", signo, target);
        }
        return OK;
    }

    if ((rp->r_flags & RS_TERMINATED) && !(rp->r_flags & RS_EXITING)) {
        return EDEADEPT;
    }

    if (!(rp->r_flags & RS_ACTIVE) && !(rp->r_flags & RS_EXITING)) {
        if (rs_verbose) {
            printf("RS: ignoring signal %d for inactive %s\n", signo, srv_to_string(rp));
        }
        return OK;
    }

    if (rs_verbose) {
        printf("RS: %s got %s signal %d\n", srv_to_string(rp), SIGS_IS_TERMINATION(signo) ? "termination" : "non-termination", signo);
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

