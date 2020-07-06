find_program(INF2CAT_PROGRAM
	inf2cat
	PATHS "${WDK_ROOT}/bin/${WDK_VERSION}/x86" # no x64 version of the tool
	NO_DEFAULT_PATH
)

if (NOT INF2CAT_PROGRAM)
	message(FATAL_ERROR "Failed to find inf2cat.exe")
endif()

find_program(SIGNTOOL_PROGRAM
	signtool
	PATHS "${WDK_ROOT}/bin/${WDK_VERSION}/${WDK_PLATFORM}"
	NO_DEFAULT_PATH
)

if (NOT SIGNTOOL_PROGRAM)
	message(FATAL_ERROR "Failed to find signtool.exe")
endif()

if (NOT "${ZFSIN_SIGNTOOL_CERTSTORE}")
	set(ZFSIN_SIGNTOOL_CERTSTORE PrivateCertStore CACHE STRING "Name of the certificate store (PrivateCertStore) that contains the test certificate.")
endif()
if (NOT "${ZFSIN_SIGNTOOL_CERTNAME}")
	set(ZFSIN_SIGNTOOL_CERTNAME "Contoso.com(Test)" CACHE STRING "Name of the certificate (Contoso.com(Test)) that is installed in the specified certificate store.")
endif()
if (NOT "${ZFSIN_SIGNTOOL_TSA}")
	set(ZFSIN_SIGNTOOL_TSA "http://timestamp.digicert.com" CACHE STRING "Specifies URL of the TSA (http://timestamp.digicert.com) which will time stamp the digital signature.")
endif()

add_definitions(
	-D_CRT_SECURE_NO_WARNINGS
	-D_CRT_NONSTDC_NO_WARNINGS
)
list(APPEND WDK_COMPILE_DEFINITIONS	-D_KERNEL)
list(APPEND WDK_COMPILE_FLAGS
	$<IF:$<CONFIG:Debug>,/MTd,/MT>
)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_definitions(-D__x86_32__ -D__i386 -D__i386__ -D_LP32 -DWIN32)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_definitions(-D__x86_64__ -D_LP64 -D__x86_64 -D_AMD64_ -D_WIN64 -DAMD64 -DWIN64)
else()
    message(FATAL_ERROR "Unsupported architecture")
endif()

set(CMAKE_C_STANDARD_LIBRARIES "")
add_compile_options(
	/we4013 # 'function' undefined; assuming extern returning int

	/wd4057 # 'operator' : 'identifier1' indirection to slightly different base types from 'identifier2'
	/wd4100 # 'identifier' : unreferenced formal parameter
	/wd4152 # nonstandard extension, function/data pointer conversion in expression
	/wd4200 # nonstandard extension used : zero-sized array in struct/union
	/wd4201 # nonstandard extension used : nameless struct/union
	/wd4211 # nonstandard extension used: redefined extern to static
	/wd4204 # nonstandard extension used: non-constant aggregate initializer
	/wd4210 # nonstandard extension used : function given file scope
	/wd4389 # 'operator' : signed/unsigned mismatch
	/wd4706 # assignment within conditional expression
	/wd4131 # uses old-style declarator
	/wd4115 # named type definition in parentheses
	/wd4018 # '>=': signed/unsigned mismatch
	/wd4206 # nonstandard extension used: translation unit is empty
	/wd4324 # structure was padded due to alignment specifier
	/wd4053 # one void operand for '?:'
)
string(REPLACE "/W3" "/W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
string(REGEX REPLACE "[-/]DWIN32" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

set(CRT_LINK_REGEX "/M[TD]d?")
string(REGEX MATCH "${CRT_LINK_REGEX}" CRT_FLAG_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
string(REGEX REPLACE "${CRT_LINK_REGEX}" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")

string(REGEX MATCH "${CRT_LINK_REGEX}" CRT_FLAG_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL}")
string(REGEX REPLACE "${CRT_LINK_REGEX}" "" CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL}")

string(REGEX MATCH "${CRT_LINK_REGEX}" CRT_FLAG_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
string(REGEX REPLACE "${CRT_LINK_REGEX}" "" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")

string(REGEX MATCH "${CRT_LINK_REGEX}" CRT_FLAG_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
string(REGEX REPLACE "${CRT_LINK_REGEX}" "" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")

add_compile_options(
	$<$<AND:$<CONFIG:Debug>,$<NOT:$<BOOL:$<TARGET_PROPERTY:WDK_TARGET>>>>:${CRT_FLAG_DEBUG}>
	$<$<AND:$<CONFIG:MinSizeRel>,$<NOT:$<BOOL:$<TARGET_PROPERTY:WDK_TARGET>>>>:${CRT_FLAG_MINSIZEREL}>
	$<$<AND:$<CONFIG:Release>,$<NOT:$<BOOL:$<TARGET_PROPERTY:WDK_TARGET>>>>:${CRT_FLAG_RELEASE}>
	$<$<AND:$<CONFIG:RelWithDebInfo>,$<NOT:$<BOOL:$<TARGET_PROPERTY:WDK_TARGET>>>>:${CRT_FLAG_RELWITHDEBINFO}>
)

function(um_add_executable name)
	add_executable(${ARGV})

	target_link_options(${name} PRIVATE "/MANIFESTUAC:level=\"requireAdministrator\" uiAccess=\"false\"")
	add_custom_command(
		TARGET ${name}
		POST_BUILD
		COMMAND "${SIGNTOOL_PROGRAM}" sign /v /fd sha1 /s "${ZFSIN_SIGNTOOL_CERTSTORE}" /n "${ZFSIN_SIGNTOOL_CERTNAME}" /t "${ZFSIN_SIGNTOOL_TSA}" $<TARGET_FILE:${name}>
		COMMAND "${SIGNTOOL_PROGRAM}" sign /v /as /fd sha256 /s "${ZFSIN_SIGNTOOL_CERTSTORE}" /n "${ZFSIN_SIGNTOOL_CERTNAME}" /tr "${ZFSIN_SIGNTOOL_TSA}" $<TARGET_FILE:${name}>
		WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
		VERBATIM COMMENT "Sign userspace tool"
	)
endfunction()

include_directories(BEFORE zfs/include)
add_subdirectory(spl)
add_subdirectory(zfs)

wdk_add_driver(ZFSin
  debug.c
  driver.c
  Wpp.c
)

target_link_libraries(ZFSin PRIVATE
	splkern
	zlibkern
	icpkern
	luakern
	zfskern
	zcommonkern
	nvpairkern
	unicodekern
	# WDK libraries
	WDK::WDMSEC
	WDK::STORPORT
	WDK::SCSIWMI
)

set_target_properties(ZFSin
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/driver"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/driver"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/driver"
)

configure_file(ZFSin.inf "${CMAKE_CURRENT_BINARY_DIR}/driver/ZFSin.inf" COPYONLY)

add_custom_command(
	TARGET ZFSin
	POST_BUILD
	BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/driver/ZFSin.cat"
	COMMAND "${INF2CAT_PROGRAM}" /verbose "/driver:${CMAKE_CURRENT_BINARY_DIR}/driver" /os:10_19H1_X86,10_19H1_X64,ServerRS5_X64
	COMMAND "${SIGNTOOL_PROGRAM}" sign /v /fd sha1 /s "${ZFSIN_SIGNTOOL_CERTSTORE}" /n "${ZFSIN_SIGNTOOL_CERTNAME}" /t "${ZFSIN_SIGNTOOL_TSA}" "${CMAKE_CURRENT_BINARY_DIR}/driver/ZFSin.cat"
	COMMAND "${SIGNTOOL_PROGRAM}" sign /v /as /fd sha256 /s "${ZFSIN_SIGNTOOL_CERTSTORE}" /n "${ZFSIN_SIGNTOOL_CERTNAME}" /tr "${ZFSIN_SIGNTOOL_TSA}" "${CMAKE_CURRENT_BINARY_DIR}/driver/ZFSin.cat"
	COMMAND "${SIGNTOOL_PROGRAM}" sign /v /fd sha1 /s "${ZFSIN_SIGNTOOL_CERTSTORE}" /n "${ZFSIN_SIGNTOOL_CERTNAME}" /t "${ZFSIN_SIGNTOOL_TSA}" $<TARGET_FILE:ZFSin>
	COMMAND "${SIGNTOOL_PROGRAM}" sign /v /as /fd sha256 /s "${ZFSIN_SIGNTOOL_CERTSTORE}" /n "${ZFSIN_SIGNTOOL_CERTNAME}" /tr "${ZFSIN_SIGNTOOL_TSA}" $<TARGET_FILE:ZFSin>
	WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/driver"
	VERBATIM COMMENT "Generating and signing .cat file"
)
	
install(TARGETS ZFSin RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}/driver")
install(FILES 
	"${CMAKE_CURRENT_BINARY_DIR}/driver/ZFSin.inf"
	"${CMAKE_CURRENT_BINARY_DIR}/driver/ZFSin.cat"
	DESTINATION "${CMAKE_INSTALL_BINDIR}/driver"
)

install(FILES
	$<TARGET_PDB_FILE:ZFSin>
	DESTINATION "${CMAKE_INSTALL_BINDIR}/driver"
	OPTIONAL
)
