#include "X509CertStore.h"
#include "X509DirectoryCertStore.h"

namespace digidoc{

X509CertStore* X509CertStore::instance() {
    static X509DirectoryCertStore store("../ca/ca/ca.pem");
    return &store;
}

}
