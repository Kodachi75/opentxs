# Copyright (c) Monetas AG, 2014

include_directories(SYSTEM
  ${ZEROMQ_INCLUDE_DIRS}
  ${CZMQ_INCLUDE_DIR}
)

if(OT_CRYPTO_USING_LIBSECP256K1)
  set(LIBSECP256K1 "crypto/Libsecp256k1.cpp")
  set(KEYSECP256K1 "crypto/AsymmetricKeySecp256k1.cpp")
else()
  set(LIBSECP256K1 "")
  set(KEYSECP256K1 "")
endif()

if(OT_CRYPTO_USING_TREZOR)
  set(TREZOR_TARGET "trezor-crypto")
  set(LIBTREZORCRYPTO "crypto/TrezorCrypto.cpp")
else()
  set(TREZOR_TARGET "")
  set(LIBTREZORCRYPTO "")
endif()

add_subdirectory(otprotob)
add_subdirectory(trade)
add_subdirectory(cron)
add_subdirectory(script)
add_subdirectory(recurring)

set(cxx-sources
  app/App.cpp
  app/Dht.cpp
  app/Identity.cpp
  app/Settings.cpp
  app/Wallet.cpp
  util/Tag.cpp
  util/Timer.cpp
  util/Assert.cpp
  util/StringUtils.cpp
  util/OTDataFolder.cpp
  util/OTFolders.cpp
  util/OTPaths.cpp
  transaction/Helpers.cpp
  mkcert.cpp
  Account.cpp
  AccountList.cpp
  crypto/OTASCIIArmor.cpp
  contract/UnitDefinition.cpp
  contract/CurrencyContract.cpp
  contract/SecurityContract.cpp
  contract/Signable.cpp
  contract/basket/Basket.cpp
  contract/basket/BasketContract.cpp
  contract/basket/BasketItem.cpp
  crypto/BitcoinCrypto.cpp
  crypto/OTAsymmetricKey.cpp
  crypto/OTAsymmetricKeyOpenSSL.cpp
  crypto/OTAsymmetricKeyOpenSSLPrivdp.cpp
  ${KEYSECP256K1}
  crypto/OTCachedKey.cpp
  crypto/OTCallback.cpp
  crypto/OTCaller.cpp
  Cheque.cpp
  Contract.cpp
  crypto/CredentialSet.cpp
  crypto/Crypto.cpp
  crypto/CryptoHash.cpp
  crypto/CryptoUtil.cpp
  crypto/CryptoAsymmetric.cpp
  crypto/CryptoSymmetric.cpp
  crypto/OpenSSL.cpp
  ${LIBSECP256K1}
  ${LIBTREZORCRYPTO}
  crypto/CryptoEngine.cpp
  OTData.cpp
  crypto/Letter.cpp
  crypto/OTEnvelope.cpp
  Identifier.cpp
  Instrument.cpp
  Item.cpp
  crypto/KeyCredential.cpp
  crypto/OTKeypair.cpp
  crypto/OTKeyring.cpp
  Ledger.cpp
  Log.cpp
  crypto/NymParameters.cpp
  crypto/LowLevelKeyGenerator.cpp
  crypto/MasterCredential.cpp
  Message.cpp
  NumList.cpp
  crypto/OTNymOrSymmetricKey.cpp
  crypto/OTPassword.cpp
  crypto/OTPasswordData.cpp
  Nym.cpp
  contract/ServerContract.cpp
  crypto/OTSignatureMetadata.cpp
  crypto/OTSignedFile.cpp
  OTStorage.cpp
  String.cpp
  OTStringXML.cpp
  crypto/Credential.cpp
  crypto/ChildKeyCredential.cpp
  crypto/OTSymmetricKey.cpp
  OTTrackable.cpp
  OTTransaction.cpp
  OTTransactionType.cpp
  NymIDSource.cpp
  crypto/Bip32.cpp
  crypto/Bip39.cpp
  crypto/PaymentCode.cpp
  crypto/ContactCredential.cpp
  crypto/VerificationCredential.cpp
)

file(GLOB cxx-headers
     "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/core/*.hpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/core/app/*.hpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/core/crypto/*.hpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/core/transaction/*.hpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/../../include/opentxs/core/util/*.hpp"
)

include_directories(${ProtobufIncludePath})


if(KEYRING_GNOME)
  include(GNUInstallDirs)
  include_directories(${CMAKE_INSTALL_FULL_OLDINCLUDEDIR}/glib-2.0/ /usr/${CMAKE_INSTALL_LIBDIR}/glib-2.0/include/ ${CMAKE_INSTALL_FULL_OLDINCLUDEDIR}/gnome-keyring-1/)
  set(keyring libgnome-keyring.so)
endif()

include_directories(SYSTEM
  ${OPENSSL_INCLUDE_DIR}
  ${PROTOBUF_INCLUDE_DIR}
  ${ZLIB_INCLUDE_DIRS}
)

set(MODULE_NAME opentxs-core)
if(WIN32)
  # suppress warnings about exported internal symbols (global log stream objects)
  add_definitions(-DOTLOG_IMPORT)

  # suppress warnings about strcpy being unsafe in anyoption.cpp
  add_definitions(/wd4996)

  # suppress linker warnings about locallly defined imported symbols
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /ignore:4049 /ignore:4217")

  configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/windll.rc.in
    ${CMAKE_CURRENT_BINARY_DIR}/module.rc
    @ONLY
  )

  # we have an extra Windows-specific file to compile
  add_library(${MODULE_NAME}
    ${cxx-sources}
    ${cxx-headers}
    util/OTWindowsRegistryTools.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/module.rc
  )
else()
  add_library(${MODULE_NAME}
    ${cxx-sources}
    ${cxx-headers}
  )
endif()

target_link_libraries(opentxs-core PRIVATE opentxs-storage opentxs-recurring opentxs-script opentxs-cron opentxs-trade otprotob irrxml bitcoin-base58 czmq_local)
target_link_libraries(opentxs-core PUBLIC opentxs-network ${PROTOBUF_LITE_LIBRARIES} ${OPENSSL_LIBRARIES} ${ZLIB_LIBRARY} ${SODIUM_LIBRARY} ${OPENTXS_SYSTEM_LIBRARIES} ${keyring})

add_library(opentxs-proto SHARED IMPORTED)
add_library(opentxs-verify SHARED IMPORTED)

set_property(TARGET opentxs-proto PROPERTY IMPORTED_LOCATION ${OPENTXS_PROTO})
set_property(TARGET opentxs-verify PROPERTY IMPORTED_LOCATION ${OPENTXS_VERIFY})

target_link_libraries(opentxs-core PRIVATE opentxs-proto)
target_link_libraries(opentxs-core PRIVATE opentxs-verify)

if (OT_CRYPTO_USING_LIBSECP256K1)
    add_library(staticlibsecp256k1 STATIC IMPORTED)
    set_property(TARGET staticlibsecp256k1 PROPERTY IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/deps/lib/libsecp256k1.a)
    target_link_libraries(opentxs-core PRIVATE staticlibsecp256k1)
    target_link_libraries(opentxs-core PUBLIC ${GMP_LIBRARIES})
endif()

if (OT_CRYPTO_USING_TREZOR)
    target_link_libraries(opentxs-core PRIVATE ${TREZOR_TARGET})
endif()

set_lib_property(opentxs-core)

if(WIN32)
  add_custom_command(TARGET opentxs-core POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_BINARY_DIR}/lib/$<CONFIGURATION>/opentxs-core.dll"
    "${CMAKE_BINARY_DIR}/bin/$<CONFIGURATION>/opentxs-core.dll")

  add_custom_command(TARGET opentxs-core POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_BINARY_DIR}/lib/$<CONFIGURATION>/opentxs-core.pdb"
    "${CMAKE_BINARY_DIR}/bin/$<CONFIGURATION>/opentxs-core.pdb")
endif()

if(NOT WIN32)
  include(GNUInstallDirs)
  install(TARGETS opentxs-core
          DESTINATION ${CMAKE_INSTALL_LIBDIR}
          EXPORT opentxsTargets
          COMPONENT main)
endif()
