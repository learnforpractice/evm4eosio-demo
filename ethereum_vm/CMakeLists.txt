if (EOSIO_COMPILE_ETHEREUM_VM_CONTRACTS)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package( eosio.cdt REQUIRED )

add_contract(ethereum_vm ethereum_vm ethereum_vm.cpp)

# target_include_directories(ethereum_vm
#    PUBLIC
#    ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(ethereum_vm
   PROPERTIES
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/ethereum_vm.abi ${CMAKE_CURRENT_BINARY_DIR}/ethereum_vm.abi @COPYONLY )

else()

#add_contract( utility utility utility.cpp )
add_library(ethereum_vm eth_account.cpp
    ${CMAKE_SOURCE_DIR}/externals/eosio.contracts/contracts/eosio.token/src/eosio.token.cpp
)

target_include_directories(ethereum_vm
   PRIVATE ${CMAKE_SOURCE_DIR}/externals/eosio.contracts/contracts/eosio.token/include
   PRIVATE "${CMAKE_SOURCE_DIR}/contracts/include"
   #                              PRIVATE "${CMAKE_SOURCE_DIR}/contracts/include/libcxx"
   #                              PRIVATE "${CMAKE_SOURCE_DIR}/contracts/include/libc"
   PRIVATE "${CMAKE_SOURCE_DIR}/contracts/include/eosiolib/core"
   PRIVATE "${CMAKE_SOURCE_DIR}/contracts/include/eosiolib/capi"
   PRIVATE "${CMAKE_SOURCE_DIR}/contracts/include/eosiolib/contracts"
)

target_compile_options( ethereum_vm PRIVATE -DEOSIO_NATIVE -Wno-unknown-attributes )

install(TARGETS ethereum_vm
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

endif()


