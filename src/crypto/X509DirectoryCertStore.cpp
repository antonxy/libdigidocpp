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

/*
 * Alternative implementation of X509CertStore that uses a directory/file-based
 * CA store instead of TSL. Swap this file for X509CertStore.cpp in CMakeLists.txt.
 */

#include "X509CertStore.h"

#include "Conf.h"
#include "crypto/OpenSSLHelpers.h"
#include "crypto/X509Cert.h"
#include "util/DateTime.h"
#include "util/log.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

using namespace digidoc;
using namespace std;

const X509CertStore::Type X509CertStore::CA {
    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
};

const X509CertStore::Type X509CertStore::TSA {
    "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
};

const X509CertStore::Type X509CertStore::OCSP {
    "http://uri.etsi.org/TrstSvc/Svctype/CA/QC",
    "http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC",
};

struct X509CertStore::Private
{
    string caPath;
};

X509CertStore::X509CertStore()
    : d(make_unique<Private>())
{
    d->caPath = CONF(CaFilePath);
    DEBUG("X509DirectoryCertStore initialized with CA path: %s", d->caPath.c_str());
}

X509CertStore::~X509CertStore() noexcept = default;

X509CertStore* X509CertStore::instance()
{
    static X509CertStore INSTANCE;
    return &INSTANCE;
}

void X509CertStore::activate(const X509Cert & /*cert*/) const
{
    // No-op for directory-based store
}

vector<X509Cert> X509CertStore::certs(const Type & /*type*/) const
{
    // Not implemented for directory-based store
    return {};
}

X509Cert X509CertStore::findIssuer(const X509Cert & /*cert*/, const Type & /*type*/) const
{
    // Not implemented for directory-based store
    return {};
}

X509Cert X509CertStore::issuerFromAIA(const X509Cert & /*cert*/)
{
    // Not implemented - issuer must be in CA file
    return {};
}

unique_free_t<X509_STORE> X509CertStore::createStore(const Type & /*type*/, tm &tm)
{
    auto store = make_unique_ptr(X509_STORE_new(), X509_STORE_free);
    if(!store)
        THROW_OPENSSLEXCEPTION("Failed to create X509_STORE");

    string caPath = CONF(CaFilePath);
    DEBUG("Loading CA from: %s", caPath.c_str());
    if(!X509_STORE_load_locations(store.get(), caPath.c_str(), nullptr))
        THROW_OPENSSLEXCEPTION("Failed to load CA file: %s", caPath.c_str());

    X509_STORE_set_flags(store.get(), X509_V_FLAG_USE_CHECK_TIME | X509_V_FLAG_CRL_CHECK);
    X509_VERIFY_PARAM_set_time(X509_STORE_get0_param(store.get()), util::date::mkgmtime(tm));
    ERR_clear_error();
    return store;
}

void X509CertStore::update() const
{
    // No-op for directory-based store
}

bool X509CertStore::verify(const X509Cert &cert, bool noqscd, tm validation_time) const
{
    if(!noqscd)
        throw Exception(__FILE__, __LINE__, "QSCD verification not implemented for directory-based store");

    DEBUG("Verifying certificate against directory store: %s", d->caPath.c_str());

    auto store = make_unique_ptr(X509_STORE_new(), X509_STORE_free);
    if(!store)
        THROW_OPENSSLEXCEPTION("Failed to create X509_STORE");

    if(!X509_STORE_load_locations(store.get(), d->caPath.c_str(), nullptr))
        THROW_OPENSSLEXCEPTION("Failed to load CA file: %s", d->caPath.c_str());

    auto csc = make_unique_ptr<X509_STORE_CTX_free>(X509_STORE_CTX_new());
    if(!X509_STORE_CTX_init(csc.get(), store.get(), cert.handle(), nullptr))
        THROW_OPENSSLEXCEPTION("Failed to init X509_STORE_CTX");

    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(csc.get());
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);

    if(!util::date::is_empty(validation_time))
    {
        DEBUG("Using validation time: %s", util::date::to_string(validation_time).c_str());
        X509_VERIFY_PARAM_set_time(param, util::date::mkgmtime(validation_time));
    }

    if(X509_verify_cert(csc.get()) > 0)
        return true;

    int err = X509_STORE_CTX_get_error(csc.get());
    DEBUG("Verification failed: %s", X509_verify_cert_error_string(err));

    OpenSSLException e(EXCEPTION_PARAMS("%s", X509_verify_cert_error_string(err)));
    if(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
        e.setCode(Exception::CertificateIssuerMissing);
    throw e;
}

int X509CertStore::validate(int ok, X509_STORE_CTX * /*ctx*/)
{
    // Simple pass-through for directory-based store
    return ok;
}
