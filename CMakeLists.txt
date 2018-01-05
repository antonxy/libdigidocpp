cmake_minimum_required(VERSION 3.0)
project(libdigidocpp VERSION 3.13.2)
if(POLICY CMP0063)
    cmake_policy(SET CMP0063 NEW)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

include(VersionInfo)
include(GNUInstallDirs)

set_env( TSL_URL "https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml" CACHE STRING "TSL trust list primary URL" )
set_env( TSL_CERT1 "${CMAKE_CURRENT_SOURCE_DIR}/etc/tl-mp1.crt" CACHE FILEPATH "TSL trust list signing certificate" )
set_env( TSL_CERT2 "${CMAKE_CURRENT_SOURCE_DIR}/etc/tl-mp2.crt" CACHE FILEPATH "TSL trust list signing certificate" )
set_env( TSL_CERT3 "${CMAKE_CURRENT_SOURCE_DIR}/etc/tl-mp3.crt" CACHE FILEPATH "TSL trust list signing certificate" )
set_env( TSL_CERT4 "${CMAKE_CURRENT_SOURCE_DIR}/etc/tl-mp4.crt" CACHE FILEPATH "TSL trust list signing certificate" )
set_env( TSA_URL "http://tsa.sk.ee" CACHE STRING "Default TSA URL" )
set_env( SIVA_URL "https://siva.eesti.ee/validate" CACHE STRING "Default SiVa validation service URL" )
set( LIBDIGIDOC_LINKED YES CACHE BOOL "Link with libdigidoc or load runtime with dlopen" )
set( BUILD_TOOLS YES CACHE BOOL "Build digidoc-tool" )
set( BUILD_TYPE SHARED CACHE STRING "Build library as SHARED/STATIC" )
set( SIGNCERT "" CACHE STRING "Common name of certificate to used sign binaries, empty skip signing" )
set( INSTCERT "" CACHE STRING "Common name of certificate to used sign packages, empty skip signing" )
if( APPLE )
    set( FRAMEWORK YES CACHE BOOL "Build library as Mac OS X Framework" )
    set( USE_KEYCHAIN YES CACHE BOOL "Use keychain to store PKCS12 access certificate" )
endif()

find_package(Doxygen)
find_package(LibDigiDoc)
find_package(OpenSSL 1.0.1 REQUIRED)
find_package(PKCS11)
find_package(Threads)
find_package(XercesC REQUIRED)
find_package(XmlSecurityC REQUIRED)
find_package(XSD 4.0 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(MiniZip QUIET)
find_package(SWIG)

if( DOXYGEN_FOUND )
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/etc/Doxyfile.in Doxyfile @ONLY )
    add_custom_target( docs ALL
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
    install( DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR} )
    install( DIRECTORY doc/ DESTINATION ${CMAKE_INSTALL_DOCDIR} )
endif()

if( WIN32 )
    add_definitions( -DUNICODE -D_CRT_SECURE_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN )
endif()

if(NOT MINIZIP_FOUND)
    message(STATUS "MiniZip not found; using bundled copy.")
    if(WIN32)
        list( APPEND MINIZIP_SRCS src/minizip/iowin32.c )
    endif()
    add_library( minizip STATIC src/minizip/zip.c src/minizip/unzip.c src/minizip/ioapi.c ${MINIZIP_SRCS} )
    if(CMAKE_COMPILER_IS_GNUCC OR __COMPILER_GNU)
        set_target_properties( minizip PROPERTIES COMPILE_FLAGS "-fPIC -Wno-unused-parameter" )
    endif()
    set_target_properties( minizip PROPERTIES COMPILE_DEFINITIONS "NOUNCRYPT;NOCRYPT" )
    set( MINIZIP_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/minizip )
    set( MINIZIP_LIBRARIES minizip )
endif()

set( DIGIDOCPP_CONFIG_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/digidocpp" )

if( USE_KEYCHAIN )
    list( APPEND digidocpp_DEFS USE_KEYCHAIN )
    list( APPEND TARGET_LIBRARIES "-framework Security" )
endif()

if(ANDROID)
    find_package(Iconv)
    list( APPEND TARGET_LIBRARIES ${ICONV_LIBRARIES} )
endif()

set(SCHEMA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/etc/schema)
set(XML_DIR ${CMAKE_CURRENT_BINARY_DIR}/xml)
XSD_SCHEMA( xsd_SRCS IGNORE ${XML_DIR} ${SCHEMA_DIR}/conf.xsd
     --root-element configuration )
XSD_SCHEMA( xsd_SRCS IGNORE ${XML_DIR} ${SCHEMA_DIR}/OpenDocument_manifest.xsd
    --root-element manifest
    --namespace-map urn:oasis:names:tc:opendocument:xmlns:manifest:1.0=digidoc::manifest )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/xmldsig-core-schema.xsd
    --root-element-none
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --custom-type ObjectType=/ObjectTypeBase
    --hxx-epilogue \"\#include <xml/ObjectType.h>\" )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/XAdES01903v132-201601.xsd
    --root-element-none
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades
    --custom-type AnyType=/AnyTypeBase
    --custom-type UnsignedSignaturePropertiesType=/UnsignedSignaturePropertiesTypeBase
    --ordered-type UnsignedSignaturePropertiesType
    --hxx-epilogue \"\#include <xml/AnyType.h>\"
    --hxx-epilogue \"\#include <xml/UnsignedSignaturePropertiesType.h>\" )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/XAdES01903v141-201601.xsd
    --root-element-none
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades
    --namespace-map http://uri.etsi.org/01903/v1.4.1\#=digidoc::xadesv141)
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/en_31916201v010101.xsd
    --root-element XAdESSignatures
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades
    --namespace-map http://uri.etsi.org/02918/v1.2.1\#=digidoc::asic )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/OpenDocument_dsig.xsd
    --root-element document-signatures
    --namespace-map urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0=digidoc::asic
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig)
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/xml.xsd
    --root-element-none )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/ts_119612v020201_201601xsd.xsd
    --root-element TrustServiceStatusList
    --namespace-map http://uri.etsi.org/02231/v2\#=digidoc::tsl
    --namespace-map http://www.w3.org/2000/09/xmldsig\#=digidoc::dsig
    --custom-type AdditionalInformationType=/AdditionalInformationTypeBase
    --custom-type ExtensionType=/ExtensionTypeBase
    --hxx-epilogue \"\#include <xml/ExtensionType.h>\"
    --hxx-epilogue \"\#include <xml/AdditionalInformationType.h>\" )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/ts_119612v020101_additionaltypes_xsd.xsd
    --root-element-none
    --namespace-map http://uri.etsi.org/02231/v2\#=digidoc::tsl
    --namespace-map http://uri.etsi.org/02231/v2/additionaltypes\#=digidoc::tsl
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades )
XSD_SCHEMA( xsd_SRCS XML_HEADER ${XML_DIR} ${SCHEMA_DIR}/ts_119612v020101_sie_xsd.xsd
    --root-element-none
    --accessor-regex /assert/assert_/
    --modifier-regex /assert/assert_/
    --namespace-map http://uri.etsi.org/02231/v2\#=digidoc::tsl
    --namespace-map http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/\#=digidoc::tsl
    --namespace-map http://uri.etsi.org/01903/v1.3.2\#=digidoc::xades )
if( WIN32 )
    add_executable( embedfile embedfile.cpp )
    add_custom_command( OUTPUT tslcert1.h tslcert2.h tslcert3.h tslcert4.h
        COMMAND $<TARGET_FILE:embedfile> ${TSL_CERT1} tslcert1_crt tslcert1.h
        COMMAND $<TARGET_FILE:embedfile> ${TSL_CERT2} tslcert2_crt tslcert2.h
        COMMAND $<TARGET_FILE:embedfile> ${TSL_CERT3} tslcert3_crt tslcert3.h
        COMMAND $<TARGET_FILE:embedfile> ${TSL_CERT4} tslcert4_crt tslcert4.h
        COMMENT "Generating tslcert1.h from ${TSL_CERT1}, tslcert2.h from ${TSL_CERT2}, tslcert3.h from ${TSL_CERT3}, tslcert4.h from ${TSL_CERT4}"
    )
else()
    add_custom_command( OUTPUT tslcert1.h tslcert2.h tslcert3.h tslcert4.h
        COMMAND ln -sf ${TSL_CERT1} tslcert1.crt
        COMMAND ln -sf ${TSL_CERT2} tslcert2.crt
        COMMAND ln -sf ${TSL_CERT3} tslcert3.crt
        COMMAND ln -sf ${TSL_CERT4} tslcert4.crt
        COMMAND xxd -i tslcert1.crt tslcert1.h
        COMMAND xxd -i tslcert2.crt tslcert2.h
        COMMAND xxd -i tslcert3.crt tslcert3.h
        COMMAND xxd -i tslcert4.crt tslcert4.h
        COMMENT "Generating tslcert1.h from ${TSL_CERT1}, tslcert2.h from ${TSL_CERT2}, tslcert3.h from ${TSL_CERT3}, tslcert4.h from ${TSL_CERT4}"
    )
endif()
list( APPEND digidocpp_SRCS tslcert1.h tslcert2.h tslcert3.h tslcert4.h )

set( SCHEMA_FILES
    ${SCHEMA_DIR}/conf.xsd
    ${SCHEMA_DIR}/OpenDocument_manifest.xsd
    ${SCHEMA_DIR}/xmldsig-core-schema.xsd
    ${SCHEMA_DIR}/XAdES01903v132-201601.xsd
    ${SCHEMA_DIR}/XAdES01903v132-201601-relaxed.xsd
    ${SCHEMA_DIR}/XAdES01903v141-201601.xsd
    ${SCHEMA_DIR}/en_31916201v010101.xsd
    ${SCHEMA_DIR}/xml.xsd
    ${SCHEMA_DIR}/ts_119612v020201_201601xsd.xsd
    ${SCHEMA_DIR}/ts_119612v020101_additionaltypes_xsd.xsd
    ${SCHEMA_DIR}/ts_119612v020101_sie_xsd.xsd
    ${SCHEMA_DIR}/OpenDocument_dsig.xsd
)

if( WIN32 )
    list( APPEND digidocpp_SRCS crypto/WinSigner.cpp )
    list( APPEND CRYPTO_HEADER crypto/WinSigner.h )
    list( APPEND TARGET_LIBRARIES Crypt32 cryptui ncrypt Ws2_32 )
elseif( APPLE )
    list( APPEND TARGET_LIBRARIES "-framework CoreFoundation" )
endif()

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${XERCESC_INCLUDE_DIR}
    ${XMLSECURITYC_INCLUDE_DIRS}
    ${XSD_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIR}
    ${MINIZIP_INCLUDE_DIR}
)

add_library(digidocpp_priv STATIC
    ${xsd_SRCS}
    src/log.cpp
    src/crypto/Connect.cpp
    src/crypto/Digest.cpp
    src/crypto/X509Crypto.cpp
    src/util/File.cpp
    src/util/DateTime.cpp
    src/xml/AdditionalInformationType.cpp
    src/xml/AnyType.cpp
    src/xml/ExtensionType.cpp
    src/xml/ObjectType.cpp
    src/xml/SecureDOMParser.cpp
    src/xml/UnsignedSignaturePropertiesType.cpp
    src/xml/URIResolver.cpp
)

set_target_properties(digidocpp_priv PROPERTIES
    COMPILE_DEFINITIONS "DIGIDOCPP_CONFIG_DIR=\"${DIGIDOCPP_CONFIG_DIR}\""
    POSITION_INDEPENDENT_CODE YES
)
target_include_directories(digidocpp_priv PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(digidocpp_priv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(digidocpp ${BUILD_TYPE}
    ${digidocpp_SRCS}
    #${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf
    ${CMAKE_CURRENT_SOURCE_DIR}/etc/878252.p12
    ${SCHEMA_FILES}
    ${PUBLIC_HEADER}
    ${CRYPTO_HEADER}
    ${XML_HEADER}
    #libdigidocpp.rc
    src/Container.cpp
    src/ASiContainer.cpp
    src/ASiC_E.cpp
    src/SiVaContainer.cpp
    src/Conf.cpp
    src/XmlConf.cpp
    src/DataFile.cpp
    src/Exception.cpp
    src/Signature.cpp
    src/SignatureXAdES_B.cpp
    src/crypto/PKCS11Signer.cpp
    src/crypto/PKCS12Signer.cpp
    src/crypto/Signer.cpp
    src/crypto/X509Cert.cpp
    src/crypto/X509CertStore.cpp
    src/crypto/X509DirectoryCertStore.cpp
    src/util/ZipSerialize.cpp
)

target_include_directories(digidocpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)


set_target_properties(digidocpp PROPERTIES
    COMPILE_DEFINITIONS "PKCS11_MODULE=\"${PKCS11_MODULE}\";TSA_URL=\"${TSA_URL}\";TSL_URL=\"${TSL_URL}\";SIVA_URL=\"${SIVA_URL}\";${digidocpp_DEFS}"
    VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}
    SOVERSION 1
    PUBLIC_HEADER "${PUBLIC_HEADER}"
    RESOURCE "${CMAKE_CURRENT_BINARY_DIR}/digidocpp.conf;${CMAKE_CURRENT_SOURCE_DIR}/etc/878252.p12"
    FRAMEWORK_VERSION 1
    FRAMEWORK "${FRAMEWORK}"
    MACOSX_FRAMEWORK_IDENTIFIER "ee.ria.digidocpp"
    MACOSX_RPATH YES
)

target_link_libraries(digidocpp digidocpp_priv
    ${CMAKE_DL_LIBS}
    ${MINIZIP_LIBRARIES}
    ${XERCESC_LIBRARIES}
    ${XMLSECURITYC_LIBRARIES}
    ${TARGET_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    ${ZLIB_LIBRARIES}
)

install( TARGETS digidocpp
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    RESOURCE DESTINATION ${DIGIDOCPP_CONFIG_DIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/digidocpp
    FRAMEWORK DESTINATION /Library/Frameworks
)
