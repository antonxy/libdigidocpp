#include "digidocpp/crypto/X509CertStore.h"
#include "digidocpp/crypto/X509DirectoryCertStore.h"
#include "digidocpp/Conf.h"

namespace digidoc{

X509CertStore* X509CertStore::instance() {
    static X509DirectoryCertStore store(CONF(CaFilePath));
    return &store;
}

}
