#include <iostream>
#include "erpiko/p11-token.h"
#include "erpiko/rsakey.h"
#include "erpiko/utils.h"
#include "erpiko/data-source.h"
#include "erpiko/digest.h"
#include "erpiko/certificate.h"
#include "erpiko/enveloped-data.h"
#include "erpiko/signed-data.h"

using namespace std;
using namespace Erpiko;

int main() {
        cout << "Hello, world!" << endl;

        P11Token p11Token;
        Token& t  = (Token&)p11Token;
        auto r = t.load("/usr/lib/libeTPkcs11.so");
        if (r != true) {
                cout << "Failed to load lib" << endl;
                return 1;
        }
        cout << "Please insert the smartcard to slot" << endl;
        /*
         * */
        int slotId;
        auto status = t.waitForCardStatus(slotId);
        if (status == CardStatus::NOT_PRESENT) {
                cout << "Token not present, please put it back...";
                status = t.waitForCardStatus(slotId);
        }

        if (status != CardStatus::PRESENT) {
                cout << "Token is not present." << endl;
                return 1;
        }

        r = t.login(slotId, "qwerty");
        if (r != true) {
                cout << "Failed to login" << endl;
                return 1;
        }
        return 0;
}
