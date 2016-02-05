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

#ifndef OPENTXS_CORE_CRYPTO_ASYMMETRICKEYSECP256K1_HPP
#define OPENTXS_CORE_CRYPTO_ASYMMETRICKEYSECP256K1_HPP

#include <opentxs/core/OTData.hpp>
#include <opentxs/core/crypto/OTAsymmetricKey.hpp>
#include <opentxs/core/crypto/LowLevelKeyGenerator.hpp>

namespace opentxs
{

class OTCaller;
class OTPassword;
class String;

class AsymmetricKeySecp256k1 : public OTAsymmetricKey
{
private:
    typedef OTAsymmetricKey ot_super;
    friend class OTAsymmetricKey; // For the factory.
    friend class LowLevelKeyGenerator;

    AsymmetricKeySecp256k1();
    AsymmetricKeySecp256k1(const proto::KeyRole role);
    AsymmetricKeySecp256k1(const proto::AsymmetricKey& serializedKey);
    AsymmetricKeySecp256k1(const String& publicKey);
    void ReleaseKeyLowLevel_Hook() const override;
    // used by LowLevelKeyGenerator
    std::unique_ptr<OTData> key_;

public:
    CryptoAsymmetric& engine() const override;
    bool IsEmpty() const override;
    bool SetKey(const OTData& key, bool isPrivate);
    bool GetKey(OTData& key) const;
    bool GetPublicKey(String& strKey) const override;
    bool ReEncryptPrivateKey(const OTPassword& theExportPassword,
                                     bool bImporting) const override;
    void Release_AsymmetricKeySecp256k1();
    void Release() override;
    virtual ~AsymmetricKeySecp256k1();

    serializedAsymmetricKey Serialize() const override;
    bool TransportKey(unsigned char* publicKey, unsigned char* privateKey) const override;
};

} // namespace opentxs

#endif // OPENTXS_CORE_CRYPTO_ASYMMETRICKEYSECP256K1_HPP
