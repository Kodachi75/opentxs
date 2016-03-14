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

#include <opentxs/core/crypto/ContactCredential.hpp>

#include <opentxs-proto/verify/VerifyContacts.hpp>

#include <opentxs/core/Log.hpp>
#include <opentxs/core/OTStorage.hpp>
#include <opentxs/core/Proto.hpp>
#include <opentxs/core/String.hpp>
#include <opentxs/core/app/App.hpp>
#include <opentxs/core/crypto/CredentialSet.hpp>
#include <opentxs/core/util/OTFolders.hpp>

namespace opentxs
{
// static
Claim ContactCredential::asClaim(
        const String& nymid,
        const uint32_t section,
        const proto::ContactItem& item)
{
    std::set<uint32_t> attributes;

    for (auto& attrib: item.attribute()) {
        attributes.insert(attrib);
    }

    proto::Claim preimage;
    preimage.set_version(1);
    preimage.set_nymid(nymid.Get(), nymid.GetLength());
    preimage.set_section(section);
    preimage.set_type(item.type());
    preimage.set_start(item.start());
    preimage.set_end(item.end());
    preimage.set_value(item.value());

    OTData hash;
    App::Me().Crypto().Hash().Digest(
        CryptoHash::HASH160,
        proto::ProtoAsData<proto::Claim>(preimage),
        hash);
    String ident = App::Me().Crypto().Util().Base58CheckEncode(hash);

    return Claim{ident.Get(), section, item.type(), item.value(),
        item.start(), item.end(), attributes};
}

ContactCredential::ContactCredential(
    CredentialSet& parent,
    const proto::Credential& credential)
        : ot_super(parent, credential)
{
    master_id_ = credential.childdata().masterid();
    data_.reset(new proto::ContactData(credential.contactdata()));
}

ContactCredential::ContactCredential(
    CredentialSet& parent,
    const NymParameters& nymParameters)
        : ot_super(parent, nymParameters)
{
    role_ = proto::CREDROLE_CONTACT;
    nym_id_ = parent.GetNymID();
    master_id_ = parent.GetMasterCredID();

    auto contacts = nymParameters.ContactData();
    if (contacts) {
        data_.reset(new proto::ContactData(*contacts));
    }
}

bool ContactCredential::GetContactData(
        std::shared_ptr<proto::ContactData>& contactData) const
{
    if (!data_) {
        return false;
    }

    contactData = std::make_shared<proto::ContactData>(*data_);

    return bool(contactData);
}

serializedCredential ContactCredential::asSerialized(
    SerializationModeFlag asPrivate,
    SerializationSignatureFlag asSigned) const
{
    serializedCredential serializedCredential =
        this->ot_super::asSerialized(asPrivate, asSigned);

    serializedCredential->clear_signature(); //this fixes a bug, but shouldn't
    if (asSigned) {
        SerializedSignature masterSignature = MasterSignature();

        if (masterSignature) {
            // We do not own this pointer.
            proto::Signature* serializedMasterSignature = serializedCredential->add_signature();
            *serializedMasterSignature = *masterSignature;
        } else {
            otErr << __FUNCTION__ << ": Failed to get master signature.\n";
        }
    }

    *(serializedCredential->mutable_contactdata()) = *data_;

    return serializedCredential;
}

} // namespace opentxs
