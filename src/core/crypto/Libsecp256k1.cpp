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

#include <opentxs/core/crypto/Libsecp256k1.hpp>

#include <opentxs/core/Log.hpp>
#include <opentxs/core/Nym.hpp>
#include <opentxs/core/crypto/Crypto.hpp>
#include <opentxs/core/app/App.hpp>
#include <opentxs/core/crypto/CryptoUtil.hpp>
#include <opentxs/core/crypto/Letter.hpp>
#include <opentxs/core/crypto/NymParameters.hpp>
#include <opentxs/core/crypto/OTASCIIArmor.hpp>
#include <opentxs/core/crypto/OTAsymmetricKey.hpp>
#include <opentxs/core/crypto/OTEnvelope.hpp>
#include <opentxs/core/crypto/OTKeypair.hpp>
#include <opentxs/core/crypto/OTPassword.hpp>
#include <opentxs/core/crypto/OTPasswordData.hpp>
#include <opentxs/core/crypto/OTSymmetricKey.hpp>
#include <opentxs/core/crypto/OTSignature.hpp>
#include <opentxs/core/crypto/AsymmetricKeySecp256k1.hpp>
#include <opentxs/core/crypto/Letter.hpp>

#include <vector>

namespace opentxs
{

Libsecp256k1::Libsecp256k1(CryptoUtil& ssl)
    : Crypto(),
    context_(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)),
    ssl_(ssl)
{
    OT_ASSERT_MSG(nullptr != context_, "Libsecp256k1::Libsecp256k1: secp256k1_context_create failed.");
}


bool Libsecp256k1::Sign(
    const OTData& plaintext,
    const OTAsymmetricKey& theKey,
    const CryptoHash::HashType hashType,
    OTData& signature, // output
    const OTPasswordData* pPWData,
    const OTPassword* exportPassword) const
{
    OTData hash;
    bool haveDigest = App::Me().Crypto().Hash().Digest(hashType, plaintext, hash);

    if (haveDigest) {
        OTPassword privKey;
        bool havePrivateKey;

        if (nullptr == pPWData) {
            OTPasswordData passwordData("Libsecp256k1::SignContract(): Please enter your password to sign this document.");
            havePrivateKey = AsymmetricKeyToECDSAPrivkey(theKey, passwordData, privKey, exportPassword);
        } else {
            havePrivateKey = AsymmetricKeyToECDSAPrivkey(theKey, *pPWData, privKey, exportPassword);
        }

        if (havePrivateKey) {
            secp256k1_ecdsa_signature ecdsaSignature;

            bool signatureCreated = secp256k1_ecdsa_sign(
                context_,
                &ecdsaSignature,
                reinterpret_cast<const unsigned char*>(hash.GetPointer()),
                reinterpret_cast<const unsigned char*>(privKey.getMemory()),
                nullptr,
                nullptr);

            if (signatureCreated) {
                signature.Assign(ecdsaSignature.data, sizeof(secp256k1_ecdsa_signature));
                return true;
            } else {
                    otErr << __FUNCTION__ << ": "
                    << "Call to secp256k1_ecdsa_sign() failed.\n";

                    return false;
            }
        } else {
                otErr << __FUNCTION__ << ": "
                << "Can not extract ecdsa private key from OTAsymmetricKey.\n";

                return false;
        }
    } else {
        otErr << __FUNCTION__ << ": "
        << "Failed to obtain the contract hash.\n";

        return false;
    }
}

bool Libsecp256k1::Verify(
    const OTData& plaintext,
    const OTAsymmetricKey& theKey,
    const OTData& signature,
    const CryptoHash::HashType hashType,
    __attribute__((unused)) const OTPasswordData* pPWData) const
{
    OTData hash;
    bool haveDigest = App::Me().Crypto().Hash().Digest(hashType, plaintext, hash);

    if (haveDigest) {
        secp256k1_pubkey ecdsaPubkey;
        bool havePublicKey = AsymmetricKeyToECDSAPubkey(theKey, ecdsaPubkey);

        if (havePublicKey) {
            secp256k1_ecdsa_signature ecdsaSignature;

            bool haveSignature = OTDataToECDSASignature(signature, ecdsaSignature);

            if (haveSignature) {
                bool signatureVerified = secp256k1_ecdsa_verify(
                    context_,
                    &ecdsaSignature,
                    reinterpret_cast<const unsigned char*>(hash.GetPointer()),
                    &ecdsaPubkey);

                return signatureVerified;
            }
        }
    }
    return false;
}

bool Libsecp256k1::OTDataToECDSASignature(
    const OTData& inSignature,
    secp256k1_ecdsa_signature& outSignature) const
{
    const uint8_t* sigStart = static_cast<const uint8_t*>(inSignature.GetPointer());

    if (nullptr != sigStart) {

        if (sizeof(secp256k1_ecdsa_signature) == inSignature.GetSize()) {
            secp256k1_ecdsa_signature ecdsaSignature;

            for(uint32_t i=0; i < inSignature.GetSize(); i++) {
                ecdsaSignature.data[i] = *(sigStart + i);
            }

            outSignature = ecdsaSignature;

            return true;
        }
    }
    return false;
}

bool Libsecp256k1::AsymmetricKeyToECDSAPubkey(
        const OTAsymmetricKey& asymmetricKey,
        secp256k1_pubkey& pubkey) const
{
    String encodedPubkey;
    bool havePublicKey = asymmetricKey.GetPublicKey(encodedPubkey);

    if (havePublicKey) {
        OTData serializedPubkey;
        bool pubkeydecoded = CryptoUtil::Base58CheckDecode(encodedPubkey.Get(), serializedPubkey);

        if (pubkeydecoded) {
            secp256k1_pubkey parsedPubkey;

            bool pubkeyParsed = secp256k1_ec_pubkey_parse(
                context_,
                &parsedPubkey,
                reinterpret_cast<const unsigned char*>(serializedPubkey.GetPointer()),
                serializedPubkey.GetSize());

            if (pubkeyParsed) {
                pubkey = parsedPubkey;
                return true;
            }
        }
    }
    return false;
}

bool Libsecp256k1::ECDSAPubkeyToAsymmetricKey(
        const secp256k1_pubkey& pubkey,
        OTAsymmetricKey& asymmetricKey) const
{
    OTData serializedPubkey;

    bool keySerialized = secp256k1_pubkey_serialize(serializedPubkey, pubkey);

    if (keySerialized) {
        return static_cast<AsymmetricKeySecp256k1&>(asymmetricKey).SetKey(serializedPubkey, false);
    }
    return false;
}

bool Libsecp256k1::AsymmetricKeyToECDSAPrivkey(
    const OTAsymmetricKey& asymmetricKey,
    const OTPasswordData& passwordData,
    OTPassword& privkey,
    const OTPassword* exportPassword) const
{
    OTData dataPrivkey;
    bool havePrivateKey = static_cast<const AsymmetricKeySecp256k1&>(asymmetricKey).GetKey(dataPrivkey);

    OT_ASSERT(0 < dataPrivkey.GetSize());

    if (havePrivateKey) {
        return AsymmetricKeyToECDSAPrivkey(dataPrivkey, passwordData, privkey, exportPassword);
    } else {
        return false;
    }
}

bool Libsecp256k1::AsymmetricKeyToECDSAPrivkey(
    const OTData& asymmetricKey,
    const OTPasswordData& passwordData,
    OTPassword& privkey,
    const OTPassword* exportPassword) const
{

    BinarySecret masterPassword(App::Me().Crypto().AES().InstantiateBinarySecretSP());

    if (nullptr == exportPassword) {
        masterPassword = CryptoSymmetric::GetMasterKey(passwordData);
        return ImportECDSAPrivkey(asymmetricKey, *masterPassword, privkey);
    } else {
        return ImportECDSAPrivkey(asymmetricKey, *exportPassword, privkey);
    }

}

bool Libsecp256k1::ImportECDSAPrivkey(
    const OTData& asymmetricKey,
    const OTPassword& password,
    OTPassword& privkey) const
{
    return DecryptPrivateKey(asymmetricKey, password, privkey);
}

bool Libsecp256k1::ECDSAPrivkeyToAsymmetricKey(
        const OTPassword& privkey,
        const OTPasswordData& passwordData,
        OTAsymmetricKey& asymmetricKey) const
{
    BinarySecret masterPassword(App::Me().Crypto().AES().InstantiateBinarySecretSP());

    masterPassword = CryptoSymmetric::GetMasterKey(passwordData, true);

    return ExportECDSAPrivkey(privkey, *masterPassword, asymmetricKey);
}

bool Libsecp256k1::ExportECDSAPrivkey(
    const OTPassword& privkey,
    const OTPassword& password,
    OTAsymmetricKey& asymmetricKey) const
{
    OTData encryptedKey;

    EncryptPrivateKey(privkey, password, encryptedKey);

    return static_cast<AsymmetricKeySecp256k1&>(asymmetricKey).SetKey(encryptedKey, true);
}

bool Libsecp256k1::EncryptPrivateKey(
    const OTPassword& plaintextKey,
    const OTPassword& password,
    OTData& encryptedKey)
{
    OTPassword keyPassword;
    App::Me().Crypto().Hash().Digest(CryptoHash::SHA256, password, keyPassword);

    return App::Me().Crypto().AES().Encrypt(
        CryptoSymmetric::AES_256_ECB,
        keyPassword,
        static_cast<const char*>(plaintextKey.getMemory()),
        plaintextKey.getMemorySize(),
        encryptedKey);
}

bool Libsecp256k1::DecryptPrivateKey(
    const OTData& encryptedKey,
    const OTPassword& password,
    OTPassword& plaintextKey)
{
    OTPassword keyPassword;
    App::Me().Crypto().Hash().Digest(CryptoHash::SHA256, password, keyPassword);

    return App::Me().Crypto().AES().Decrypt(
        CryptoSymmetric::AES_256_ECB,
        keyPassword,
        static_cast<const char*>(encryptedKey.GetPointer()),
        encryptedKey.GetSize(),
        plaintextKey);
}

bool Libsecp256k1::ECDH(
    const OTAsymmetricKey& publicKey,
    const OTAsymmetricKey& privateKey,
    const OTPasswordData& passwordData,
    OTPassword& secret) const
{
    OTPassword scalar;
    secp256k1_pubkey point;

    bool havePrivateKey = AsymmetricKeyToECDSAPrivkey(privateKey, passwordData, scalar);

    if (havePrivateKey) {
        bool havePublicKey = AsymmetricKeyToECDSAPubkey(publicKey, point);

        if (havePublicKey) {
            secret.SetSize(PrivateKeySize);

            return secp256k1_ecdh(
                context_,
                reinterpret_cast<unsigned char*>(secret.getMemoryWritable()),
                &point,
                static_cast<const unsigned char*>(scalar.getMemory()));
        } else {
            otErr << "Libsecp256k1::" << __FUNCTION__ << " could not obtain public key.\n.";
            return false;
        }
    } else {
        otErr << "Libsecp256k1::" << __FUNCTION__ << " could not obtain private key.\n.";
        return false;
    }
}

bool Libsecp256k1::EncryptSessionKeyECDH(
        const OTPassword& sessionKey,
        const OTAsymmetricKey& privateKey,
        const OTAsymmetricKey& publicKey,
        const OTPasswordData& passwordData,
        symmetricEnvelope& encryptedSessionKey) const
{
    CryptoSymmetric::Mode algo = CryptoSymmetric::StringToMode(std::get<0>(encryptedSessionKey));
    CryptoHash::HashType hmac = CryptoHash::StringToHashType(std::get<1>(encryptedSessionKey));

    if (CryptoSymmetric::ERROR_MODE == algo) {
        otErr << "Libsecp256k1::" << __FUNCTION__ << ": Unsupported encryption algorithm.\n";
        return false;
    }

    if (CryptoHash::ERROR == hmac) {
        otErr << "Libsecp256k1::" << __FUNCTION__ << ": Unsupported hmac algorithm.\n";
        return false;
    }

    OTData nonce;
    String nonceReadable = App::Me().Crypto().Util().Nonce(CryptoSymmetric::KeySize(algo), nonce);

    // Calculate ECDH shared secret
    BinarySecret ECDHSecret(App::Me().Crypto().AES().InstantiateBinarySecretSP());
    bool haveECDH = ECDH(publicKey, privateKey, passwordData, *ECDHSecret);

    if (haveECDH) {
        // In order to make sure the session key is always encrypted to a different key for every Seal() action,
        // even if the sender and recipient are the same, don't use the ECDH secret directly. Instead, calculate
        // an HMAC of the shared secret and a nonce and use that as the AES encryption key.
        BinarySecret sharedSecret(App::Me().Crypto().AES().InstantiateBinarySecretSP());
        App::Me().Crypto().Hash().HMAC(hmac, *ECDHSecret, nonce, *sharedSecret);

        // The values calculated above might not be the correct size for the default symmetric encryption
        // function.
        if ((sharedSecret->getMemorySize() >= CryptoSymmetric::KeySize(algo)) &&
            (nonce.GetSize() >= CryptoSymmetric::IVSize(algo))) {

            BinarySecret truncatedSharedSecret(App::Me().Crypto().AES().InstantiateBinarySecretSP());
            truncatedSharedSecret->setMemory(sharedSecret->getMemory(), CryptoSymmetric::KeySize(algo));
            OTData truncatedNonce(nonce.GetPointer(), CryptoSymmetric::IVSize(algo));

                OTData ciphertext, tag;
                bool encrypted = App::Me().Crypto().AES().Encrypt(
                    algo,
                    *truncatedSharedSecret,
                    truncatedNonce,
                    static_cast<const char*>(sessionKey.getMemory()),
                    sessionKey.getMemorySize(),
                    ciphertext,
                    tag);

                    if (encrypted) {
                        OTASCIIArmor encodedCiphertext(ciphertext);
                        String tagReadable(CryptoUtil::Base58CheckEncode(tag));

                        std::get<2>(encryptedSessionKey) = nonceReadable;
                        std::get<3>(encryptedSessionKey) = tagReadable;
                        std::get<4>(encryptedSessionKey) = std::make_shared<OTEnvelope>(encodedCiphertext);

                        return true;
                    } else {
                        otErr << "Libsecp256k1::" << __FUNCTION__ << ": Session key encryption failed.\n";
                        return false;
                    }
        } else {
            otErr << "Libsecp256k1::" << __FUNCTION__ << ": Insufficient nonce or key size.\n";
            return false;
        }

    } else {
        otErr << "Libsecp256k1::" << __FUNCTION__ << ": ECDH shared secret negotiation failed.\n";
        return false;
    }
}




bool Libsecp256k1::DecryptSessionKeyECDH(
    const symmetricEnvelope& encryptedSessionKey,
    const OTAsymmetricKey& privateKey,
    const OTAsymmetricKey& publicKey,
    const OTPasswordData& passwordData,
    OTPassword& sessionKey) const
{
    CryptoSymmetric::Mode algo = CryptoSymmetric::StringToMode(std::get<0>(encryptedSessionKey));
    CryptoHash::HashType hmac = CryptoHash::StringToHashType(std::get<1>(encryptedSessionKey));

    if (CryptoSymmetric::ERROR_MODE == algo) {
        otErr << "Libsecp256k1::" << __FUNCTION__ << ": Unsupported encryption algorithm.\n";
        return false;
    }

    if (CryptoHash::ERROR == hmac) {
        otErr << "Libsecp256k1::" << __FUNCTION__ << ": Unsupported hmac algorithm.\n";
        return false;
    }

    // Extract and decode the nonce
    OTData nonce;
    bool nonceDecoded = CryptoUtil::Base58CheckDecode(std::get<2>(encryptedSessionKey).Get(), nonce);

    if (nonceDecoded) {
        // Calculate ECDH shared secret
        BinarySecret ECDHSecret(App::Me().Crypto().AES().InstantiateBinarySecretSP());
        bool haveECDH = ECDH(publicKey, privateKey, passwordData, *ECDHSecret);

        if (haveECDH) {
            // In order to make sure the session key is always encrypted to a different key for every Seal() action
            // even if the sender and recipient are the same, don't use the ECDH secret directly. Instead, calculate
            // an HMAC of the shared secret and a nonce and use that as the AES encryption key.
            BinarySecret sharedSecret(App::Me().Crypto().AES().InstantiateBinarySecretSP());
            App::Me().Crypto().Hash().HMAC(hmac, *ECDHSecret, nonce, *sharedSecret);

            // The values calculated above might not be the correct size for the default symmetric encryption
            // function.
            if (
                (sharedSecret->getMemorySize() >= CryptoConfig::SymmetricKeySize()) &&
                (nonce.GetSize() >= CryptoConfig::SymmetricIvSize())) {

                    BinarySecret truncatedSharedSecret(App::Me().Crypto().AES().InstantiateBinarySecretSP());
                    truncatedSharedSecret->setMemory(sharedSecret->getMemory(), CryptoSymmetric::KeySize(algo));
                    OTData truncatedNonce(nonce.GetPointer(), CryptoSymmetric::IVSize(algo));

                    // Extract and decode the tag from the envelope
                    OTData tag;
                    CryptoUtil::Base58CheckDecode(std::get<3>(encryptedSessionKey).Get(), tag);

                    // Extract and decode the ciphertext from the envelope
                    OTData ciphertext;
                    OTASCIIArmor encodedCiphertext;
                    std::get<4>(encryptedSessionKey)->GetAsciiArmoredData(encodedCiphertext);
                    encodedCiphertext.GetData(ciphertext);

                    return App::Me().Crypto().AES().Decrypt(
                                                            algo,
                                                            *truncatedSharedSecret,
                                                            truncatedNonce,
                                                            tag,
                                                            static_cast<const char*>(ciphertext.GetPointer()),
                                                            ciphertext.GetSize(),
                                                            sessionKey);
            } else {
                otErr << "Libsecp256k1::" << __FUNCTION__ << ": Insufficient nonce or key size.\n";
                return false;
            }

        } else {
            otErr << "Libsecp256k1::" << __FUNCTION__ << ": ECDH shared secret negotiation failed.\n";
            return false;
        }

    } else {
        otErr << "Libsecp256k1::" << __FUNCTION__ << ": Can not decode nonce.\n";
        return false;
    }
}

bool Libsecp256k1::secp256k1_privkey_tweak_add(
    uint8_t key [PrivateKeySize],
    const uint8_t tweak [PrivateKeySize]) const
{
    if (nullptr != context_) {
        return secp256k1_ec_privkey_tweak_add(context_, key, tweak);
    } else {
        return false;
    }
}

bool Libsecp256k1::secp256k1_pubkey_create(
    secp256k1_pubkey& pubkey,
    const OTPassword& privkey) const
{
    if (nullptr != context_) {
        return secp256k1_ec_pubkey_create(context_, &pubkey, static_cast<const unsigned char*>(privkey.getMemory()));
    }

    return false;
}

bool Libsecp256k1::secp256k1_pubkey_serialize(
        OTData& serializedPubkey,
        const secp256k1_pubkey& pubkey) const
{
    if (nullptr != context_) {
        uint8_t serializedOutput [33] {};
        size_t serializedSize = 33;

        bool serialized = secp256k1_ec_pubkey_serialize(context_, serializedOutput, &serializedSize, &pubkey, SECP256K1_EC_COMPRESSED);

        if (serialized) {
            serializedPubkey.Assign(serializedOutput, serializedSize);
            return serialized;
        }
    }

    return false;
}

bool Libsecp256k1::secp256k1_pubkey_parse(
        secp256k1_pubkey& pubkey,
        const OTPassword& serializedPubkey) const
{
    if (nullptr != context_) {

        const uint8_t* inputStart = static_cast<const uint8_t*>(serializedPubkey.getMemory());

        bool parsed = secp256k1_ec_pubkey_parse(context_, &pubkey, inputStart, serializedPubkey.getMemorySize());

        return parsed;
    }

    return false;
}

Libsecp256k1::~Libsecp256k1()
{
    OT_ASSERT_MSG(nullptr != context_, "Libsecp256k1::~Libsecp256k1: context_ should never be nullptr, yet it was.")
    secp256k1_context_destroy(context_);
    context_ = nullptr;
}

void Libsecp256k1::Init_Override() const
{
    static bool bNotAlreadyInitialized = true;
    OT_ASSERT_MSG(bNotAlreadyInitialized, "Libsecp256k1::Init_Override: Tried to initialize twice.");
    bNotAlreadyInitialized = false;
    // --------------------------------
    uint8_t randomSeed [32]{};
    ssl_.RandomizeMemory(randomSeed, 32);

    OT_ASSERT_MSG(nullptr != context_, "Libsecp256k1::Libsecp256k1: secp256k1_context_create failed.");

    int __attribute__((unused)) randomize = secp256k1_context_randomize(context_,
                                                                        randomSeed);
}

void Libsecp256k1::Cleanup_Override() const
{
}

} // namespace opentxs
