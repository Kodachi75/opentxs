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

#include <opentxs/core/crypto/Bip32.hpp>

#include <opentxs/core/app/App.hpp>
#include <opentxs/core/crypto/OTCachedKey.hpp>

namespace opentxs
{

BinarySecret Bip32::GetHDSeed() const
{
    OTPasswordData pReason = "loading the master HD seed for this wallet";
    return CryptoSymmetric::GetMasterKey(pReason);
}

serializedAsymmetricKey Bip32::GetHDKey(proto::HDPath& path) const
{
    uint32_t depth = path.child_size();
    if (0 == depth) {
        std::string fingerprint = path.root();
        auto seed = App::Me().Crypto().BIP39().Seed(fingerprint);
        serializedAsymmetricKey node;

        if (seed) {
            node = SeedToPrivateKey(*seed);
            path.set_root(fingerprint);
        }

        return node;
    } else {
        proto::HDPath newpath = path;
        newpath.mutable_child()->RemoveLast();
        auto parentnode = GetHDKey(newpath);

        serializedAsymmetricKey node;
        if (parentnode) {
            path.set_root(newpath.root());

            node = GetChild(
                *parentnode,
                path.child(depth-1));

            if (node) {
                *(node->mutable_path()) = path;
            }
        }

        return node;
    }
}

serializedAsymmetricKey Bip32::GetPaymentCode(const uint32_t nym) const
{
    proto::HDPath path;
    path.add_child(PC_PURPOSE | HARDENED);
    path.add_child(BITCOIN_TYPE | HARDENED);
    path.add_child(nym | HARDENED);

    return GetHDKey(path);
}

} // namespace opentxs
