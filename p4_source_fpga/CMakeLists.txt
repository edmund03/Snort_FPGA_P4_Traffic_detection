set(P4NAME "switch")
set(BF_RT_JSON "${CMAKE_CURRENT_BINARY_DIR}/${P4NAME}/bf-rt.json")

set(TOFINOFLAGS "--std" "p4-16" "--target" "tofino" "--arch" "tna")
set(TOFINO2FLAGS "--std" "p4-16" "--target" "tofino2" "--arch" "t2na")
set(TOFINO3FLAGS "--std" "p4-16" "--target" "tofino3" "--arch" "t3na")

# append command line flags to internal
set(P4FLAGS_INTERNAL "${P4FLAGS}")
set(P4PPFLAGS_INTERNAL "${P4PPFLAGS}")

set(P4FLAGS_INTERNAL "${P4FLAGS_INTERNAL}" "-o" "${CMAKE_CURRENT_BINARY_DIR}/${P4NAME}")
set(P4FLAGS_INTERNAL "${P4FLAGS_INTERNAL}" "--bf-rt-schema" "${BF_RT_JSON}")
set(P4FLAGS_INTERNAL "${P4FLAGS_INTERNAL}" "-I" "${CMAKE_CURRENT_SOURCE_DIR}/shared")
set(P4FLAGS_INTERNAL "${P4FLAGS_INTERNAL}" "--display-power-budget")
set(P4FLAGS_INTERNAL "${P4FLAGS_INTERNAL}" "-g")

# FIXME: remove disabling of parser min/max depth limits (P4C-4170)
set(P4PPFLAGS_INTERNAL_TF1 "${P4PPFLAGS_INTERNAL}" "-Xp4c='--disable-power-check" "--disable-parse-depth-limit" "-T" "stage_advance:2>stage_advance.log'")
set(P4PPFLAGS_INTERNAL_TF2 "${P4PPFLAGS_INTERNAL}" "-Xp4c='-T" "stage_advance:2>stage_advance.log'")
set(P4PP_WARNING_FLAGS "-Xp4c='--Wdisable=uninitialized_out_param" "--Wdisable=uninitialized_use" "--Wdisable=unused" "--Wdisable=substitution" "--Wdisable=table-placement'")

set(TOFINO_BIN "${CMAKE_CURRENT_BINARY_DIR}/${P4NAME}/*/*.bin")
set(CONTEXT_JSON "${CMAKE_CURRENT_BINARY_DIR}/${P4NAME}/*/context.json")

set(TOFINO_PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/switch-tofino")
set(TOFINO2_PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/switch-tofino2")

set(X1_TOFINO "${TOFINO_PROGRAMS}/switch_tofino_x1.p4")
add_custom_command(OUTPUT x1_compile COMMAND ${P4C} ${TOFINOFLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF1} ${X1_TOFINO} DEPENDS ${X1_TOFINO})
add_custom_target(x1_tofino DEPENDS x1_compile ${X1_TOFINO} bf-p4c)

set(X2_TOFINO "${TOFINO_PROGRAMS}/switch_tofino_x2.p4")
add_custom_command(OUTPUT x2_compile COMMAND ${P4C} ${TOFINOFLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF1} ${X2_TOFINO} DEPENDS ${X2_TOFINO})
add_custom_target(x2_tofino DEPENDS x2_compile ${X2_TOFINO} bf-p4c)

set(X3_TOFINO "${TOFINO_PROGRAMS}/switch_tofino_x3.p4")
add_custom_command(OUTPUT x3_compile COMMAND ${P4C} ${TOFINOFLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${X3_TOFINO} DEPENDS ${X3_TOFINO})
add_custom_target(x3_tofino DEPENDS x3_compile ${X3_TOFINO} bf-p4c)

set(X4_TOFINO "${TOFINO_PROGRAMS}/switch_tofino_x4.p4")
add_custom_command(OUTPUT x4_compile COMMAND ${P4C} ${TOFINOFLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF1} ${X4_TOFINO} DEPENDS ${X4_TOFINO})
add_custom_target(x4_tofino DEPENDS x4_compile ${X4_TOFINO} bf-p4c)

set(X5_TOFINO "${TOFINO_PROGRAMS}/switch_tofino_x5.p4")
add_custom_command(OUTPUT x5_compile COMMAND ${P4C} ${TOFINOFLAGS} ${P4FLAGS_INTERNAL} ${P4PPFLAGS_INTERNAL_TF1} ${X5_TOFINO} DEPENDS ${X5_TOFINO})
add_custom_target(x5_tofino DEPENDS x5_compile ${X5_TOFINO} bf-p4c)

set(X6_TOFINO "${TOFINO_PROGRAMS}/switch_tofino_x6.p4")
add_custom_command(OUTPUT x6_compile COMMAND ${P4C} ${TOFINOFLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF1} ${X6_TOFINO} DEPENDS ${X6_TOFINO})
add_custom_target(x6_tofino DEPENDS x6_compile ${X6_TOFINO} bf-p4c)

set(Y0_TOFINO2 "${TOFINO2_PROGRAMS}/switch_tofino2_y0.p4")
add_custom_command(OUTPUT y0_compile COMMAND ${P4C} ${TOFINO2FLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF2} ${Y0_TOFINO2} DEPENDS ${Y0_TOFINO2})
add_custom_target(y0_tofino2 DEPENDS y0_compile ${Y0_TOFINO2} bf-p4c)

set(Y1_TOFINO2 "${TOFINO2_PROGRAMS}/switch_tofino2_y1.p4")
add_custom_command(OUTPUT y1_compile COMMAND ${P4C} ${TOFINO2FLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF2} ${Y1_TOFINO2} DEPENDS ${Y1_TOFINO2})
add_custom_target(y1_tofino2 DEPENDS y1_compile ${Y1_TOFINO2} bf-p4c)

set(Y2_TOFINO2 "${TOFINO2_PROGRAMS}/switch_tofino2_y2.p4")
add_custom_command(OUTPUT y2_compile COMMAND ${P4C} ${TOFINO2FLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF2} ${Y2_TOFINO2} DEPENDS ${Y2_TOFINO2})
add_custom_target(y2_tofino2 DEPENDS y2_compile ${Y2_TOFINO2} bf-p4c)

set(Y3_TOFINO2 "${TOFINO2_PROGRAMS}/switch_tofino2_y3.p4")
add_custom_command(OUTPUT y3_compile COMMAND ${P4C} ${TOFINO2FLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF2} ${Y3_TOFINO2} DEPENDS ${Y3_TOFINO2})
add_custom_target(y3_tofino2 DEPENDS y3_compile ${Y3_TOFINO2} bf-p4c)

set(Y4_TOFINO2 "${TOFINO2_PROGRAMS}/switch_tofino2_y4.p4")
add_custom_command(OUTPUT y4_compile COMMAND ${P4C} ${TOFINO2FLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF2} ${Y4_TOFINO2} DEPENDS ${Y4_TOFINO2})
add_custom_target(y4_tofino2 DEPENDS y4_compile ${Y4_TOFINO2} bf-p4c)

set(Y5_TOFINO2 "${TOFINO2_PROGRAMS}/switch_tofino2_y5.p4")
add_custom_command(OUTPUT y5_compile COMMAND ${P4C} ${TOFINO2FLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF2} ${Y5_TOFINO2} DEPENDS ${Y5_TOFINO2})
add_custom_target(y5_tofino2 DEPENDS y5_compile ${Y5_TOFINO2} bf-p4c)

set(Y7_TOFINO2 "${TOFINO2_PROGRAMS}/switch_tofino2_y7.p4")
add_custom_command(OUTPUT y7_compile COMMAND ${P4C} ${TOFINO2FLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF2} ${Y7_TOFINO2} DEPENDS ${Y7_TOFINO2})
add_custom_target(y7_tofino2 DEPENDS y7_compile ${Y7_TOFINO2} bf-p4c)

set(Z2_XP4C_FLAGS "-Xp4c=\"-Tstage_advance:1\"" "--num-stages-override" "16")
set(Z2_TOFINO2 "${TOFINO2_PROGRAMS}/switch_tofino2_z2.p4")
add_custom_command(OUTPUT z2_compile COMMAND ${P4C} ${TOFINO2FLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF2} ${Z2_XP4C_FLAGS} ${Z2_TOFINO2} DEPENDS ${Z2_TOFINO2})
add_custom_target(z2_tofino2 DEPENDS z2_compile ${Z2_TOFINO2} bf-p4c)

# build for tofino3 but use tofino2 files
set(Y2_TOFINO3 "${TOFINO2_PROGRAMS}/switch_tofino2_y2.p4")
add_custom_target(y2_tofino3
  COMMAND ${P4C} ${TOFINO3FLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF2} ${Y2_TOFINO3} DEPENDS ${Y2_TOFINO3}
  DEPENDS ${Y2_TOFINO3} bf-p4c)

set(Z2_XP4C_FLAGS "-Xp4c=\"-Tstage_advance:1\"" "--num-stages-override" "16")
set(Z2_TOFINO3 "${TOFINO2_PROGRAMS}/switch_tofino2_z2.p4")
add_custom_target(z2_tofino3
  COMMAND ${P4C} ${TOFINO3FLAGS} ${P4FLAGS_INTERNAL} ${P4PP_WARNING_FLAGS} ${P4PPFLAGS_INTERNAL_TF2} ${Z2_XP4C_FLAGS} ${Z2_TOFINO3} DEPENDS ${Z2_TOFINO3}
  DEPENDS ${Z2_TOFINO3} bf-p4c)

# install 3 files only
# bf-rt.json, tofino.bin/tofino2.bin/tofino3.bin, context.json
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/switch/ DESTINATION share/switch
  FILES_MATCHING
  FILES_MATCHING 
  PATTERN "*.json"
  PATTERN "*.bin"
  PATTERN "logs" EXCLUDE
  PATTERN "graphs" EXCLUDE
  PATTERN "*dynhash*" EXCLUDE
  PATTERN "*prim*" EXCLUDE
  )
