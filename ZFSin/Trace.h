#pragma once

#define WPPNAME		ZFSinTraceGuid
#define WPPGUID		c20c603c,afd4,467d,bf76,c0a4c10553df

#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(WPPNAME,(WPPGUID), \
        WPP_DEFINE_BIT(MYDRIVER_ALL_INFO)             /* bit  0 = 0x00000001 */ \
        WPP_DEFINE_BIT(TRACE_DRIVER)           /* bit  1 = 0x00000002 */ \
        WPP_DEFINE_BIT(TRACE_DEVICE)              /* bit  2 = 0x00000004 */ \
        WPP_DEFINE_BIT(TRACE_QUEUE)           /* bit  3 = 0x00000008 */ )

#ifndef WPP_CHECK_INIT
#define WPP_CHECK_INIT
#endif


#define WPP_FLAGS_LEVEL_LOGGER(Flags, level)                                  \
    WPP_LEVEL_LOGGER(Flags)

#define WPP_FLAGS_LEVEL_ENABLED(Flags, level)                                 \
    (WPP_LEVEL_ENABLED(Flags) && \
    WPP_CONTROL(WPP_BIT_ ## Flags).Level >= level)

#define WPP_LEVEL_FLAGS_LOGGER(lvl,flags) \
           WPP_LEVEL_LOGGER(flags)

#define WPP_LEVEL_FLAGS_ENABLED(lvl, flags) \
           (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= lvl)

// begin_wpp config
// FUNC dprintf{FLAGS=MYDRIVER_ALL_INFO, LEVEL=TRACE_LEVEL_INFORMATION}(MSG, ...);
// end_wpp