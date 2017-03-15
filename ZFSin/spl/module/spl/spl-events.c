
#if 1 // KERNEL EVENTS EXAMPLE


#include <sys/kern_event.h>
#include <spl-events.h>

static u_int32_t vendor_code = 0;

kern_return_t spl_notification_init(void)
{
    int error = 0;

    error = kev_vendor_code_find("net.lundman.spl.notification",
                                 &vendor_code);
    printf("SPL: Registered vendor %d\n", vendor_code);
    return KERN_SUCCESS;
}

int spl_notification_fini(void)
{
    return KERN_SUCCESS;
}

int spl_notification_send(int event_class, int event_subclass, int event_code)
{
    int error = 0;
    struct kev_msg ev_msg;
    bzero(&ev_msg, sizeof (ev_msg));
    ev_msg.vendor_code      = vendor_code;
    ev_msg.kev_class        = event_class;
    ev_msg.kev_subclass     = event_subclass;
    ev_msg.event_code       = event_code;
    error = kev_msg_post(&ev_msg);
    printf("Posted message: %d:%d:%d -> %d\n",
           event_class, event_subclass, event_code, error);
    return error;
}

#endif






#if 0 // KERNEL CONTROL EXAMPLE

#include <sys/kern_control.h>
static kern_ctl_ref     kctlref;

/* A simple setsockopt handler */

errno_t EPHandleSet( kern_ctl_ref ctlref, unsigned int unit, void *userdata, int opt, void *data, size_t len )

{
    int    error = EINVAL;

    printf( "EPHandleSet opt is %d\n", opt);

#if 0
    switch ( opt )
    {
        case kEPCommand1:               // program defined symbol
            error = Do_First_Thing();
            break;

        case kEPCommand2:               // program defined symbol
            error = Do_Command2();
            break;
    }
#endif
    return error;
}


/* A simple A simple getsockopt handler */
errno_t EPHandleGet(kern_ctl_ref ctlref, unsigned int unit, void *userdata, int opt, void *data, size_t *len)
{
    int    error = EINVAL;
    printf( "EPHandleGet opt is %d *****************\n", opt);
    return error;
}

/* A minimalist connect handler */
errno_t
EPHandleConnect(kern_ctl_ref ctlref, struct sockaddr_ctl *sac, void **unitinfo)
{
    kern_return_t ret;

    printf( "EPHandleConnect called\n");

    // Say hello
    ret = ctl_enqueuedata(ctlref,
                          sac->sc_unit,
                          "HELLO\n", 7,
                          CTL_DATA_EOR);
    printf("Sending hello %d (unit %x)\n", ret,sac->sc_unit);

	struct kev_msg ev_msg;

	ev_msg.vendor_code    = KEV_VENDOR_APPLE;
	ev_msg.kev_class      = KEV_SYSTEM_CLASS;
	ev_msg.kev_subclass   = KEV_MEMORYSTATUS_SUBCLASS;

	ev_msg.event_code     = event_code;

	ev_msg.dv[0].data_length = data_length;
	ev_msg.dv[0].data_ptr = data;
	ev_msg.dv[1].data_length = 0;

	ret = kev_post_msg(&ev_msg);

    return (0);
}

/* A minimalist disconnect handler */
errno_t
EPHandleDisconnect(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo)
{
    printf( "EPHandleDisconnect called\n");
    return 0;
}

/* A minimalist write handler */
errno_t EPHandleWrite(kern_ctl_ref ctlref, unsigned int unit, void *userdata, mbuf_t m, int flags)
{
    printf( "EPHandleWrite called\n");
    return (0);
}




kern_return_t spl_notification_init(void)
{
    errno_t error;
    struct kern_ctl_reg     ep_ctl; // Initialize control
    bzero(&ep_ctl, sizeof(ep_ctl));  // sets ctl_unit to 0
    ep_ctl.ctl_id = 0; /* OLD STYLE: ep_ctl.ctl_id = kEPCommID; */
    ep_ctl.ctl_unit = 0;
    strcpy(ep_ctl.ctl_name, "net.lundman.spl.notification");
    ep_ctl.ctl_flags = CTL_FLAG_PRIVILEGED;
    ep_ctl.ctl_send = EPHandleWrite;
    ep_ctl.ctl_getopt = EPHandleGet;
    ep_ctl.ctl_setopt = EPHandleSet;
    ep_ctl.ctl_connect = EPHandleConnect;
    ep_ctl.ctl_disconnect = EPHandleDisconnect;
    error = ctl_register(&ep_ctl, &kctlref);
    printf("ctl_register said %d (unit %04x)\n", error, ep_ctl.ctl_unit);
    return KERN_SUCCESS;
}

#define SPL_QUIT_MESSAGE "Q\000"

int spl_notification_fini(void)
{
    int error;
    ctl_enqueuedata(kctlref,
                    0,
                    SPL_QUIT_MESSAGE, strlen(SPL_QUIT_MESSAGE),
                    CTL_DATA_EOR);
    error = ctl_deregister(kctlref);
    printf("ctl_deregister said %d\n", error);
    return error;
}
#endif
