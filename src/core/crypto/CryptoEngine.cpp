/************************************************************
 *
 *                 OPEN TRANSACTIONS
 *
 *       Financial Cryptography and Digital Cash
 *       Library, Protocol, API, Server, CLI, GUI
 *
 *       -- Anonymous Numbered Accounts.
 *       -- Untraceable Digital Cash.
 *       -- Triple-Signed Receipts.
 *       -- Cheques, Vouchers, Transfers, Inboxes.
 *       -- Basket Currencies, Markets, Payment Plans.
 *       -- Signed, XML, Ricardian-style Contracts.
 *       -- Scripted smart contracts.
 *
 *  EMAIL:
 *  fellowtraveler@opentransactions.org
 *
 *  WEBSITE:
 *  http://www.opentransactions.org/
 *
 *  -----------------------------------------------------
 *
 *   LICENSE:
 *   This Source Code Form is subject to the terms of the
 *   Mozilla Public License, v. 2.0. If a copy of the MPL
 *   was not distributed with this file, You can obtain one
 *   at http://mozilla.org/MPL/2.0/.
 *
 *   DISCLAIMER:
 *   This program is distributed in the hope that it will
 *   be useful, but WITHOUT ANY WARRANTY; without even the
 *   implied warranty of MERCHANTABILITY or FITNESS FOR A
 *   PARTICULAR PURPOSE.  See the Mozilla Public License
 *   for more details.
 *
 ************************************************************/

#include <opentxs/core/app/App.hpp>

#include <opentxs/core/stdafx.hpp>
#include <opentxs/core/Log.hpp>

extern "C" {
#ifdef _WIN32
#else
#include <sys/resource.h>
#endif
}


namespace opentxs
{

CryptoEngine* CryptoEngine::pInstance_ = nullptr;

CryptoEngine::CryptoEngine()
{
    pSSL_.reset(new SSLImplementation);
    #ifdef OT_CRYPTO_SUPPORTED_KEY_SECP256K1
    psecp256k1_.reset(new Libsecp256k1(*pSSL_));
    #endif
    #ifdef OT_CRYPTO_USING_TREZOR
    pbitcoincrypto_.reset(new TrezorCrypto());
    #endif

    Init();
}

void CryptoEngine::Init()
{
    otWarn << "CryptoEngine::Init: Setting up rlimits, and crypto libraries...\n";

    // Here is a security measure intended to make it more difficult to
    // capture a core dump. (Not used in debug mode, obviously.)
    //
#if !defined(PREDEF_MODE_DEBUG) && defined(PREDEF_PLATFORM_UNIX)
    struct rlimit rlim;
    getrlimit(RLIMIT_CORE, &rlim);
    rlim.rlim_max = rlim.rlim_cur = 0;
    if (setrlimit(RLIMIT_CORE, &rlim)) {
        OT_FAIL_MSG("Crypto::Init: ASSERT: setrlimit failed. (Used for "
                    "preventing core dumps.)\n");
    }
#endif

    pSSL_->Init();
#if defined OT_CRYPTO_SUPPORTED_KEY_SECP256K1
    // WARNING: The below call to psecp256k1_->Init() DEPENDS on the fact
    // that the above call to pSSL_->Init() happened FIRST.
    psecp256k1_->Init();
#endif

}

CryptoUtil& CryptoEngine::Util()
{
    OT_ASSERT(nullptr != pSSL_);

    return *pSSL_;
}

CryptoHash& CryptoEngine::Hash()
{
    OT_ASSERT(nullptr != pSSL_);

    return *pSSL_;
}

#ifdef OT_CRYPTO_SUPPORTED_KEY_RSA
CryptoAsymmetric& CryptoEngine::RSA()
{
    OT_ASSERT(nullptr != pSSL_);

    return *pSSL_;
}
#endif
#ifdef OT_CRYPTO_SUPPORTED_KEY_SECP256K1
CryptoAsymmetric& CryptoEngine::SECP256K1()
{
    OT_ASSERT(nullptr != psecp256k1_);

    return *psecp256k1_;
}
#endif
#ifdef OT_CRYPTO_SUPPORTED_KEY_RSA
CryptoSymmetric& CryptoEngine::AES()
{
    OT_ASSERT(nullptr != pSSL_);

    return *pSSL_;
}
#endif
#ifdef OT_CRYPTO_WITH_BIP39
Bip39& CryptoEngine::BIP39()
{
    OT_ASSERT(nullptr != pbitcoincrypto_);

    return *pbitcoincrypto_;
}
#endif
#ifdef OT_CRYPTO_WITH_BIP32
Bip32& CryptoEngine::BIP32()
{
    OT_ASSERT(nullptr != pbitcoincrypto_);

    return *pbitcoincrypto_;
}
#endif
CryptoEngine& CryptoEngine::It()
{
    if (nullptr == pInstance_)
    {
        pInstance_ = new CryptoEngine;
    }

    return *pInstance_;
}

void CryptoEngine::Cleanup()
{
#if defined OT_CRYPTO_SUPPORTED_KEY_SECP256K1
    psecp256k1_->Cleanup();
#endif

    pSSL_->Cleanup();
}

CryptoEngine::~CryptoEngine()
{
    Cleanup();
}

} // namespace opentxs
