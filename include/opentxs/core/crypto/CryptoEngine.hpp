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

#ifndef OPENTXS_CORE_CRYPTO_CRYPTOENGINE_HPP
#define OPENTXS_CORE_CRYPTO_CRYPTOENGINE_HPP

#include <memory>

#include <opentxs/core/crypto/Bip39.hpp>
#include <opentxs/core/crypto/Bip32.hpp>
#include <opentxs/core/crypto/CryptoAsymmetric.hpp>
#include <opentxs/core/crypto/CryptoHash.hpp>
#include <opentxs/core/crypto/CryptoSymmetric.hpp>
#include <opentxs/core/crypto/CryptoUtil.hpp>

#ifdef OT_CRYPTO_USING_OPENSSL
#include <opentxs/core/crypto/OpenSSL.hpp>
#else //No SSL library defined
// Perhaps error out here...
#endif

#ifdef OT_CRYPTO_USING_LIBSECP256K1
#include <opentxs/core/crypto/Libsecp256k1.hpp>
#endif

#ifdef OT_CRYPTO_USING_TREZOR
#include <opentxs/core/crypto/TrezorCrypto.hpp>
#endif

namespace opentxs
{

// Choose your OpenSSL-compatible library here.
#ifdef OT_CRYPTO_USING_OPENSSL
typedef OpenSSL SSLImplementation;
#else //No SSL library defined
// Perhaps error out here...
#endif

#if defined OT_CRYPTO_USING_LIBSECP256K1
typedef Libsecp256k1 secp256k1;
#endif

#if defined OT_CRYPTO_USING_TREZOR
typedef TrezorCrypto bitcoincrypto;
#endif

//Singlton class for providing an interface to external crypto libraries
//and hold the state required by those libraries.
class CryptoEngine
{
private:
    CryptoEngine();
    CryptoEngine(const CryptoEngine&) = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;
    void Init();
    std::unique_ptr<SSLImplementation> pSSL_;
#ifdef OT_CRYPTO_SUPPORTED_KEY_SECP256K1
    std::unique_ptr<secp256k1> psecp256k1_;
#endif
#ifdef OT_CRYPTO_USING_TREZOR
    std::unique_ptr<bitcoincrypto> pbitcoincrypto_;
#endif
    static CryptoEngine* pInstance_;

public:
    //Utility class for misc OpenSSL-provided functions
    EXPORT CryptoUtil& Util();
    //Hash function interface
    EXPORT CryptoHash& Hash();
    //Asymmetric encryption engines
#ifdef OT_CRYPTO_SUPPORTED_KEY_RSA
    EXPORT CryptoAsymmetric& RSA();
#endif
#ifdef OT_CRYPTO_SUPPORTED_KEY_SECP256K1
    EXPORT CryptoAsymmetric& SECP256K1();
#endif
    //Symmetric encryption engines
#ifdef OT_CRYPTO_SUPPORTED_KEY_RSA
    EXPORT CryptoSymmetric& AES();
#endif
#ifdef OT_CRYPTO_WITH_BIP39
    EXPORT Bip39& BIP39();
#endif
#ifdef OT_CRYPTO_WITH_BIP32
    EXPORT Bip32& BIP32();
#endif

    EXPORT static CryptoEngine& It();
    void Cleanup();
    ~CryptoEngine();
};

}  // namespace opentxs
#endif // OPENTXS_CORE_CRYPTO_CRYPTOENGINE_HPP
