/*
 * libdigidocpp
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "digidocpp/Container.h"

#include "ASiC_E.h"
#include "digidocpp/DataFile.h"
#include "digidocpp/Exception.h"
#include "digidocpp/Signature.h"
#include "log.h"
#include "digidocpp/XmlConf.h"
#include "digidocpp/crypto/X509CertStore.h"
#include "util/File.h"

#include <xercesc/util/XMLString.hpp>
#ifdef __APPLE__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wnull-conversion"
#endif
#include <xsec/utils/XSECPlatformUtils.hpp>
#ifndef XSEC_NO_XALAN
#include <xalanc/XPath/XPathEvaluator.hpp>
#include <xalanc/XalanTransformer/XalanTransformer.hpp>
XALAN_USING_XALAN(XPathEvaluator)
XALAN_USING_XALAN(XalanTransformer)
#endif
#ifdef __APPLE__
#pragma GCC diagnostic pop
#endif

#include <algorithm>
#include <sstream>
#include <thread>

using namespace digidoc;
using namespace std;
using namespace xercesc;

typedef Container* (*plugin)(const std::string &);

namespace digidoc
{
static string m_appInfo = "libdigidocpp";
static vector<plugin> m_createList = vector<plugin>();
static vector<plugin> m_openList = vector<plugin>();
}

/**
 * @class digidoc::Container
 * @brief Offers functionality for handling data files and signatures in a container.
 *
 * Container can contain several files and all these files can be signed using
 * signing certificates. Container can only be signed if it contains data files.
 * data files can be added and removed from container only if the container is
 * not signed. To add or remove data files from signed container remove all the
 * signatures before modifying data files list in container.
 */

/**
 * Returns registered application name
 */
string digidoc::appInfo() { return m_appInfo; }

/**
 * Returns libdigidocpp library version
 */
string digidoc::version() {
    string ver = VER_STR(MAJOR_VER.MINOR_VER.RELEASE_VER.BUILD_VER);
#if defined(DYNAMIC_LIBDIGIDOC) || defined(LINKED_LIBDIGIDOC)
    ver += "_ddoc";
#endif
    return ver;
}

/**
 * Libdigidocpp’s initialization method: initializes dependent libraries,
 * loads configuration settings from default configuration files (see \ref conf) and initializes
 * certificate store using TSL lists
 *
 * @param appInfo Application name for user agent string
 * @param callBack Callback when background thread TSL loading is completed
 */
void digidoc::initialize(const string &appInfo, initCallBack callBack)
{
    m_appInfo = appInfo;

    try {
        XMLPlatformUtils::Initialize();
#ifndef XSEC_NO_XALAN
        XPathEvaluator::initialize();
        XalanTransformer::initialize();
#endif
        XSECPlatformUtils::Initialise();
    }
    catch (const XMLException &e) {
        char *msg = XMLString::transcode(e.getMessage());
        string result = msg;
        XMLString::release(&msg);
        THROW("Error during initialisation of Xerces: %s", result.c_str());
    }

    if(!Conf::instance())
        Conf::init(new XmlConfCurrent);


    if(callBack)
    {
        thread([=](){
            try {
                X509CertStore::instance();
                callBack(nullptr);
            }
            catch(const Exception &e) {
                callBack(&e);
            }
        }).detach();
    }
    else
        X509CertStore::instance();
}

/**
 * The termination method closes libraries used in Libdigidocpp
 * implementation and deletes temporary files that may have been
 * written to disk when working with the library.
 */
void digidoc::terminate()
{
    Conf::init(0);

    XSECPlatformUtils::Terminate();
#ifndef XSEC_NO_XALAN
    XalanTransformer::terminate();
    XPathEvaluator::terminate();
#endif
    XMLPlatformUtils::Terminate();

    util::File::deleteTempFiles();
    m_appInfo.clear();
}

/**
 * Create a new container object and specify the DigiDoc container type
 */
Container::Container()
{
}

/**
 * Releases resources.
 */
Container::~Container()
{
}

/**
 * @fn digidoc::Container::addDataFile(const std::string &path, const std::string &mediaType)
 * Adds data file from file system to the container.
 *
 * @param path a data file, which is added to the container.
 * @param mediaType MIME type of the data file, for example “text/plain” or “application/msword”
 * @throws Exception exception is thrown if the data file path is incorrect or a data file
 * with same file name already exists. Also, no data file can be added if the container
 * already has one or more signatures.
 * @note Data files can be removed from container only after all signatures are removed.
 */

/**
 * @fn digidoc::Container::addDataFile(std::istream *is, const std::string &fileName, const std::string &mediaType)
 * Adds the data from an input stream (i.e. the data file contents can be read from internal memory buffer)
 *
 * @param is input stream from where data is read
 * @param fileName data file name in the container
 * @param mediaType MIME type of the data file, for example “text/plain” or “application/msword”
 * @throws Exception exception is thrown if the data file path is incorrect or a data file
 * with same file name already exists. Also, no data file can be added if the container
 * already has one or more signatures.
 * @note Data files can be removed from container only after all signatures are removed.
 */

/**
 * Adds signature to the container.
 *
 * @param signature signature, which is added to the container.
 * @throws Exception throws exception if there are no data files in container.
 */
void Container::addAdESSignature(const std::vector<unsigned char> &signature)
{
    std::stringstream s(std::string(&signature[0], &signature[0] + signature.size()));
    addAdESSignature(s);
}

/**
 * @fn digidoc::Container::addAdESSignature(std::istream &signature)
 * Adds signature to the container.
 *
 * @param signature signature, which is added to the container.
 * @throws Exception throws exception if there are no data files in container.
 */

/**
 * Create a new container object and specify the DigiDoc container type
 */
Container* Container::create(const std::string &path)
{
    for(auto create: m_createList)
    {
        if(Container *container = create(path))
            return container;
    }
    return ASiC_E::createInternal(path);
}

/**
 * @fn digidoc::Container::dataFiles
 * List of all the data files in the container
 */

/**
 * @fn digidoc::Container::mediaType
 * Returns current data file format
 */

/**
 * Returns unique signature id
 */
unsigned int Container::newSignatureId() const
{
    unsigned int id = 0;
    while(true)
    {
        bool found = false;
        for(Signature *s: signatures())
        {
            if(s->id() == Log::format("S%u", id))
            {
                found = true;
                break;
            }
        }
        if(!found)
            return id;
        ++id;
    }
    return id;
}

/**
 * Opens container from a file
 *
 * @param path
 * @throws Exception
 */
Container* Container::open(const string &path)
{
    for(auto open: m_openList)
    {
        if(Container *container = open(path))
            return container;
    }
    return ASiC_E::openInternal(path);
}

/**
 * @fn digidoc::Container::removeDataFile
 * Removes data file from container by data file index. Data files can be
 * removed from container only after all signatures are removed.
 *
 * @param index data file's index, which will be removed.
 * @throws Exception throws exception if the data file id is incorrect or there are
 * one or more signatures.
 * @see digidoc::Container::dataFiles
 */

/**
 * @fn digidoc::Container::removeSignature
 * Removes signature from container by signature index.
 *
 * @param index signature's index, which will be removed.
 * @throws Exception throws exception if the signature id is incorrect.
 * @see digidoc::Container::signatures
 */

/**
 * @fn digidoc::Container::save
 * Saves the container.
 *
 * @throws Exception is thrown if there was a failure saving BDOC container. For example added
 * data file does not exist.
 */

/**
 * @fn digidoc::Container::sign(Signer *signer)
 * Signs all data files in container.
 *
 * @param signer signer implementation.
 * @throws Exception exception is thrown if signing the container failed.
 */

template<class T>
void Container::addContainerImplementation()
{
    m_createList.push_back(&T::createInternal);
    m_openList.push_back(&T::openInternal);
}

/**
 * @fn digidoc::Container::signatures
 * Returns list of all container's signatures.
 */
