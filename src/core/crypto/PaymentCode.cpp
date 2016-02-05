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

#include <opentxs/core/crypto/PaymentCode.hpp>

#include <opentxs/core/Log.hpp>
#include <opentxs/core/Proto.hpp>
#include <opentxs/core/crypto/AsymmetricKeySecp256k1.hpp>
#include <opentxs/core/app/App.hpp>
#include <opentxs/core/crypto/MasterCredential.hpp>
#include <opentxs/core/crypto/OTPassword.hpp>

namespace opentxs
{

PaymentCode::PaymentCode(const std::string& base58)
{
    OTData rawCode;
    App::Me().Crypto().Util().Base58CheckDecode(base58, rawCode);

    if (81 == rawCode.GetSize()) {
        uint8_t prependByte, features;
        rawCode.OTfread(&prependByte, 1);

        rawCode.OTfread(&version_, 1);
        rawCode.OTfread(&features, 1);

        if (features & 0x80) {
            hasBitmessage_ = true;
        }

        OTData key;
        key.SetSize(33);
        chain_code_.SetSize(32);

        OT_ASSERT(33 == key.GetSize());
        OT_ASSERT(32 == chain_code_.GetSize());

        rawCode.OTfread(static_cast<uint8_t*>(const_cast<void*>(key.GetPointer())), key.GetSize());
        rawCode.OTfread(static_cast<uint8_t*>(const_cast<void*>(chain_code_.GetPointer())), chain_code_.GetSize());

        ConstructKey(key, chain_code_);

        if (hasBitmessage_) {
            rawCode.OTfread(&bitmessage_version_, 1);
            rawCode.OTfread(&bitmessage_stream_, 1);
        }
    }
}

PaymentCode::PaymentCode(const proto::PaymentCode& paycode)
    : version_(paycode.version())
    , chain_code_(paycode.chaincode().c_str(), paycode.chaincode().size())
    , hasBitmessage_(paycode.has_bitmessage())
{
    OT_ASSERT(paycode.has_key());

    OTData key(paycode.key().c_str(), paycode.key().size());
    OTData chaincode(paycode.chaincode().c_str(), paycode.chaincode().size());
    ConstructKey(key, chaincode);

    if (paycode.has_bitmessageversion()) {
        bitmessage_version_ = paycode.bitmessageversion();
    }
    if (paycode.has_bitmessagestream()) {
        bitmessage_stream_ = paycode.bitmessagestream();
    }
}

PaymentCode::PaymentCode(
    const uint32_t nym,
    const bool bitmessage,
    const uint8_t bitmessageVersion,
    const uint8_t bitmessageStream)
        : hasBitmessage_(bitmessage)
        , bitmessage_version_(bitmessageVersion)
        , bitmessage_stream_(bitmessageStream)
{
    serializedAsymmetricKey privatekey =
        App::Me().Crypto().BIP32().GetPaymentCode(nym);

    chain_code_.Assign(
        privatekey->chaincode().c_str(),
        privatekey->chaincode().size());

    serializedAsymmetricKey key =
        App::Me().Crypto().BIP32().PrivateToPublic(*privatekey);

    OTData pubkey(key->key().c_str(), key->key().size());

    ConstructKey(pubkey, chain_code_);
}

bool PaymentCode::operator==(const proto::PaymentCode& rhs) const
{
    SerializedPaymentCode tempPaycode = Serialize();

    OTData LHData = proto::ProtoAsData<proto::PaymentCode>(*tempPaycode);
    OTData RHData = proto::ProtoAsData<proto::PaymentCode>(rhs);

    return (LHData == RHData);
}

const OTData PaymentCode::Pubkey() const
{
    OTData pubkey;
    pubkey.SetSize(33);

    if (pubkey_) {
        std::dynamic_pointer_cast<AsymmetricKeySecp256k1>(pubkey_)->GetKey(pubkey);
    }

    OT_ASSERT(33 == pubkey.GetSize());

    return pubkey;
}

const std::string PaymentCode::asBase58() const
{
    OTData pubkey = Pubkey();

    uint8_t serialized[81]{};

    serialized[0] = PaymentCode::BIP47_VERSION_BYTE;
    serialized[1] = version_;
    serialized[2] = hasBitmessage_ ? 0x80 : 0;
    OTPassword::safe_memcpy(
        &serialized[3],
        33,
        pubkey.GetPointer(),
        pubkey.GetSize(),
        false);
    OTPassword::safe_memcpy(
        &serialized[36],
        32,
        chain_code_.GetPointer(),
        chain_code_.GetSize(),
        false);
    serialized[68] = bitmessage_version_;
    serialized[69] = bitmessage_stream_;

    OTData binaryVersion(serialized, sizeof(serialized));

    return App::Me().Crypto().Util().Base58CheckEncode(binaryVersion).Get();
}

SerializedPaymentCode PaymentCode::Serialize() const
{
    SerializedPaymentCode serialized = std::make_shared<proto::PaymentCode>();

    serialized->set_version(version_);

    if (pubkey_) {
        OTData pubkey = Pubkey();
        serialized->set_key(pubkey.GetPointer(), pubkey.GetSize());
    }

    serialized->set_chaincode(chain_code_.GetPointer(), chain_code_.GetSize());
    serialized->set_bitmessageversion(bitmessage_version_);
    serialized->set_bitmessagestream(bitmessage_stream_);

    return serialized;
}

const Identifier PaymentCode::ID() const
{

    uint8_t core[65]{};

    OTData pubkey = Pubkey();
    OTPassword::safe_memcpy(
        &core[0],
        33,
        pubkey.GetPointer(),
        pubkey.GetSize(),
        false);
    if (chain_code_.GetSize() == 32) {
        OTPassword::safe_memcpy(
            &core[33],
            32,
            chain_code_.GetPointer(),
            chain_code_.GetSize(),
            false);
    }

    OTData dataVersion(core, sizeof(core));

    Identifier paymentCodeID;

    paymentCodeID.CalculateDigest(dataVersion);

    return paymentCodeID;
}

bool PaymentCode::Verify(const MasterCredential& credential) const
{
    serializedCredential serializedMaster =
        credential.asSerialized(
            Credential::AS_PUBLIC,
            Credential::WITHOUT_SIGNATURES);

    if (!proto::Check<proto::Credential>(
        *serializedMaster,
        0,
        0xFFFFFFFF,
        proto::CREDROLE_MASTERKEY,
        false)) {
            otErr << __FUNCTION__ << ": Invalid master credential syntax.\n";
            return false;
    }

    bool sameSource = (*this ==
            serializedMaster->masterdata().source().paymentcode());

    if (!sameSource) {
        otErr << __FUNCTION__ << ": Master credential was not derived from"
              << " this source->\n";
        return false;
    }

    SerializedSignature sourceSig = credential.SourceSignature();

    if (!sourceSig) {
        otErr << __FUNCTION__ << ": Master credential not signed by its"
              << " source.\n";
        return false;
    }

    if (!pubkey_) {
        otErr << __FUNCTION__ << ": Payment code is missing public key.\n";
        return false;
    }

    return pubkey_->Verify(
        proto::ProtoAsData<proto::Credential>(*serializedMaster),
        *sourceSig);
}

bool PaymentCode::Sign(
    const uint32_t nym,
    const Credential& credential,
    proto::Signature& sig,
    const OTPasswordData* pPWData) const
{
    if (!pubkey_) {
        otErr << __FUNCTION__ << ": Payment code not instantiated.\n";
        return false;
    }

    serializedAsymmetricKey privatekey =
        App::Me().Crypto().BIP32().GetPaymentCode(nym);

    if (!privatekey) {
        otErr << __FUNCTION__ << ": Failed to derive private key for"
              << " payment code.\n";
        return false;
    }

    OTData existingKeyData, compareKeyData;
    serializedAsymmetricKey compareKey =
    App::Me().Crypto().BIP32().PrivateToPublic(*privatekey);
    compareKey->clear_path();

    std::dynamic_pointer_cast<AsymmetricKeySecp256k1>
        (pubkey_)->GetKey(existingKeyData);
    compareKeyData.Assign(compareKey->key().c_str(), compareKey->key().size());

    if (!(existingKeyData == compareKeyData)) {
        otErr << __FUNCTION__ << ": Private key is not valid for this"
        << " payment code.\n";
        return false;
    }
    std::unique_ptr<OTAsymmetricKey>
        signingKey(OTAsymmetricKey::KeyFactory(*privatekey));

        serializedCredential serialized = credential.asSerialized(
            Credential::AS_PUBLIC,
            Credential::WITHOUT_SIGNATURES);

    bool goodSig = signingKey->Sign(
        proto::ProtoAsData<proto::Credential>(*serialized),
        sig,
        pPWData,
        nullptr,
        ID(),
        proto::SIGROLE_NYMIDSOURCE);

    return goodSig;
}

void PaymentCode::ConstructKey(const OTData& pubkey, const OTData& chaincode)
{
    proto::AsymmetricKey newKey;

    newKey.set_version(1);
    newKey.set_type(proto::AKEYTYPE_SECP256K1);
    newKey.set_mode(proto::KEYMODE_PUBLIC);
    newKey.set_role(proto::KEYROLE_SIGN);
    newKey.set_key(pubkey.GetPointer(), pubkey.GetSize());
    newKey.set_chaincode(chaincode.GetPointer(), chaincode.GetSize());

    OTAsymmetricKey* key = OTAsymmetricKey::KeyFactory(newKey);

    pubkey_.reset(key);
}

bool PaymentCode::VerifyInternally() const
{
    return(proto::Check<proto::PaymentCode>(*Serialize(), version_, version_));
}

} // namespace opentxs
