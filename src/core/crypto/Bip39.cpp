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

#include <opentxs/core/crypto/Bip39.hpp>


#include "opentxs/core/app/App.hpp"
#include "opentxs/core/crypto/OTCachedKey.hpp"

namespace opentxs
{
const CryptoSymmetric::Mode Bip39::DEFAULT_ENCRYPTION_MODE =
    CryptoSymmetric::AES_256_CBC;
const std::string Bip39::DEFAULT_PASSPHRASE = "opentxs";

std::string Bip39::SaveSeed(
    const std::string& words,
    const std::string& passphrase)
{
    OT_ASSERT(!words.empty() && !passphrase.empty());

    auto seed = App::Me().Crypto().AES().InstantiateBinarySecretSP();
    WordsToSeed(words, *seed, passphrase);

    OT_ASSERT(1 < seed->getMemorySize());

    auto fingerprint = App::Me().Crypto().BIP32().SeedToFingerprint(*seed);
    auto key = CryptoSymmetric::GetMasterKey("Generating a new BIP39 seed");

    OT_ASSERT(key);

    OTData encryptedWords, encryptedPassphrase, iv;

    bool haveIV = App::Me().Crypto().Hash().Digest(
        CryptoHash::SHA256,
        OTData(fingerprint.c_str(), fingerprint.length()),
        iv);

    if (haveIV) {
        bool haveWords =
            App::Me().Crypto().AES().Encrypt(
                *key,
                words.c_str(),
                words.length(),
                iv,
                encryptedWords);

        OT_ASSERT(haveWords);

        bool havePassphrase =
            App::Me().Crypto().AES().Encrypt(
                *key,
                passphrase.c_str(),
                passphrase.length(),
                iv,
                encryptedPassphrase);

        OT_ASSERT(havePassphrase);

        if (haveWords && havePassphrase) {
            proto::Seed serialized;
            serialized.set_version(1);
            serialized.set_words(
                static_cast<const char*>(encryptedWords.GetPointer()),
                encryptedWords.GetSize());
            serialized.set_passphrase(
                static_cast<const char*>(encryptedPassphrase.GetPointer()),
                encryptedPassphrase.GetSize());
            serialized.set_fingerprint(fingerprint);

            bool stored = App::Me().DB().Store(serialized, fingerprint);

            if (stored) {

                return fingerprint;
            }
        }
    }

    return "";
}

bool Bip39::SeedToData(const proto::Seed& seed, OTPassword& output) const
{
    if (proto::Check(seed, 0, 0xFFFFFFFF)) {
        auto key = CryptoSymmetric::GetMasterKey("Decrypting a new BIP39 seed");

        OT_ASSERT(key);

        OTData decryptedWords, decryptedPassphrase;

        OTData iv;
        bool haveIV = App::Me().Crypto().Hash().Digest(
            CryptoHash::SHA256,
            OTData(seed.fingerprint().c_str(), seed.fingerprint().length()),
            iv);

        if (haveIV) {
            bool haveWords =
                App::Me().Crypto().AES().Decrypt(
                    *key,
                    seed.words().c_str(),
                    seed.words().length(),
                    iv,
                    decryptedWords);

            OT_ASSERT(haveWords);

            bool havePassphrase =
                App::Me().Crypto().AES().Decrypt(
                    *key,
                    seed.passphrase().c_str(),
                    seed.passphrase().length(),
                    iv,
                    decryptedPassphrase);

            OT_ASSERT(havePassphrase);

            if (haveWords && havePassphrase) {
                std::string words(
                    static_cast<const char*>(decryptedWords.GetPointer()),
                    decryptedWords.GetSize());
                std::string passphrase(
                    static_cast<const char*>(decryptedPassphrase.GetPointer()),
                    decryptedPassphrase.GetSize());

                WordsToSeed(
                    words,
                    output,
                    passphrase);

                return true;
            }
        }
    }

    return false;
}

std::string Bip39::ImportSeed(
    const std::string& words,
    const std::string& passphrase)
{
    return SaveSeed(words, passphrase);
}

std::string Bip39::NewSeed()
{
    auto entropy = App::Me().Crypto().AES().InstantiateBinarySecretSP();

    if (entropy) {
        entropy->randomizeMemory(256/8);
        std::string words = toWords(*entropy);

        return SaveSeed(words, Bip39::DEFAULT_PASSPHRASE);
    }

    return "";
}

std::shared_ptr<OTPassword> Bip39::Seed(std::string& fingerprint)
{
    auto output = App::Me().Crypto().AES().InstantiateBinarySecretSP();

    OT_ASSERT(output);

    bool wantDefaultSeed = fingerprint.empty();

    if (wantDefaultSeed) {
        fingerprint = App::Me().DB().DefaultSeed();
        bool haveDefaultSeed = !fingerprint.empty();

        if (!haveDefaultSeed) {
            fingerprint = NewSeed();
        }

        if (!fingerprint.empty()) { // by now, we should have a good value here
            output = Seed(fingerprint);
        }

    } else { // want an explicitly identified seed
        std::shared_ptr<proto::Seed> serialized;
        bool loaded = App::Me().DB().Load(fingerprint, serialized);

        if (loaded && serialized) {
            std::unique_ptr<OTPassword>
                seed(App::Me().Crypto().AES().InstantiateBinarySecret());

            OT_ASSERT(seed);

            bool extracted = SeedToData(*serialized, *seed);

            if (extracted) {
                output.reset(seed.release());
            }
        }
    }

    return output;
}

} // namespace opentxs
