#ifndef SPL_EVENTS_H
#define SPL_EVENTS_H

enum spl_notification_class {
    SPL_CLASS_NOTIFY,
};

enum spl_notification_subclass {
    SPL_SUBCLASS_INFO,
};

enum spl_notification_event {
    SPL_EVENT_ZFS_LOAD,
    SPL_EVENT_ZFS_UNLOAD,
    SPL_EVENT_ZPOOL_IMPORT,
    SPL_EVENT_ZPOOL_EXPORT,
};



int spl_notification_init(void);
int spl_notification_fini(void);
int spl_notification_send(int event_class, int event_subclass, int event_code);


#endif
