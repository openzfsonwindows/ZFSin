um_add_executable(kstat kstat.c)
target_link_libraries(kstat PRIVATE libkstat)
install(TARGETS kstat RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES $<TARGET_PDB_FILE:kstat>
	DESTINATION "${CMAKE_INSTALL_BINDIR}"
	OPTIONAL
)