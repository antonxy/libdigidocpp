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

#include "digidocpp/crypto/X509DirectoryCertStore.h"

#include "digidocpp/Conf.h"
#include "log.h"
#include "crypto/OpenSSLHelpers.h"
#include "util/DateTime.h"
#include "util/File.h"

#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <iomanip>

using namespace digidoc;
using namespace std;

/**
 * X509CertStore constructor.
 */
X509DirectoryCertStore::X509DirectoryCertStore(std::string ca_directory)
    : ca_directory(ca_directory)
{
    SSL_load_error_strings();
    SSL_library_init();
    OPENSSL_config(0);
}

/**
 * Return STACK_OF(X509) containing all certs loaded from directory
 * @return STACK_OF(X509) all certs in store.
 * throws IOException
 */
vector<X509Cert> X509DirectoryCertStore::certs(const set<string> &type) const
{
    throw Exception(__FILE__, __LINE__, "Unimplemented");
}

/**
 * Searches certificate by subject and returns a copy of it if found.
 * If not found returns <code>NULL</code>.
 * NB! The returned certificate must be freed with OpenSSL function X509_free(X509* cert).
 *
 * @param subject certificate subject.
 * @return returns copy of found certificate or <code>NULL</code> if certificate was not found.
 * @throws IOException exception is thrown if copying certificate failed.
 */
X509Cert X509DirectoryCertStore::findIssuer(const X509Cert &cert, const set<string> &type) const
{
    throw Exception(__FILE__, __LINE__, "Unimplemented");
    /*SCOPE(AUTHORITY_KEYID, akid, (AUTHORITY_KEYID*)X509_get_ext_d2i(cert.handle(), NID_authority_key_identifier, 0, 0));
    for(const X509Cert &i: x509certs)
    {
        if(!akid || !akid->keyid)
        {
            if(X509_NAME_cmp(X509_get_subject_name(i.handle()), X509_get_issuer_name(cert.handle())))
                return i;
        }
        else
        {
            SCOPE(ASN1_OCTET_STRING, skid, (ASN1_OCTET_STRING*)X509_get_ext_d2i(i.handle(), NID_subject_key_identifier, 0, 0));
            if(skid.get() && ASN1_OCTET_STRING_cmp(akid->keyid, skid.get()) == 0)
                return i;
        }
    }
    return X509Cert();*/
}

X509_STORE * X509DirectoryCertStore::setup_store() const
{
    SCOPE(X509_STORE, store, X509_STORE_new());

    if (store == NULL) {
        DEBUG("Error store");
        throw Exception(__FILE__, __LINE__, "Failed to create ca store");
    }

    //DEBUG("Load ca dir");
    //X509_LOOKUP * lookup = X509_STORE_add_lookup(store.get(), X509_LOOKUP_hash_dir());
    //if (lookup == NULL) {
    //    DEBUG("Error lookup");
    //    throw Exception(__FILE__, __LINE__, "Failed to create ca dir lookup");
    //}
    //if (!X509_LOOKUP_add_dir(lookup, ca_directory.c_str(), X509_FILETYPE_PEM)) {
    //    DEBUG("Error loading directory %s", ca_directory.c_str());
    //    throw Exception(__FILE__, __LINE__, "Failed to load ca dir");
    //}

    DEBUG("Load ca file");
    X509_LOOKUP * lookup = X509_STORE_add_lookup(store.get(), X509_LOOKUP_file());
    if (lookup == NULL) {
        DEBUG("Error lookup");
        throw Exception(__FILE__, __LINE__, "Failed to create ca file lookup");
    }
    if (!X509_LOOKUP_load_file(lookup, ca_directory.c_str(), X509_FILETYPE_PEM)) {
        DEBUG("Error loading file %s", ca_directory.c_str());
        throw Exception(__FILE__, __LINE__, "Failed to load ca file");
    }

    ERR_clear_error();
    return store.release();
}

/**
 * Check if X509Cert is signed by trusted issuer
 * @throw Exception if error
 */
bool X509DirectoryCertStore::verify(const X509Cert &cert, bool noqscd) const
{
    if (!noqscd) {
        throw Exception(__FILE__, __LINE__, "qscd not imlemented");
    }
    SCOPE(X509_STORE, store, setup_store());

    SCOPE(X509_STORE_CTX, csc, X509_STORE_CTX_new());
    if(!X509_STORE_CTX_init(csc.get(), store.get(), cert.handle(), nullptr))
        THROW_OPENSSLEXCEPTION("Failed to init X509_STORE_CTX");
    if(X509_verify_cert(csc.get()) > 0) {
        return true;
    }

    int err = X509_STORE_CTX_get_error(csc.get());
    Exception e(__FILE__, __LINE__, X509_verify_cert_error_string(err), OpenSSLException());
    switch(err)
    {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        e.setCode(Exception::CertificateIssuerMissing);
        throw e;
    default: throw e;
    }
}
