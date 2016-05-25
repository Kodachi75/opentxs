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

#include <opentxs/core/crypto/VerificationCredential.hpp>

#include <opentxs/core/Proto.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/OTStorage.hpp>
#include <opentxs/core/app/App.hpp>
#include <opentxs/core/crypto/CredentialSet.hpp>
#include <opentxs/core/util/OTFolders.hpp>

namespace opentxs
{

// static
proto::Verification VerificationCredential::SigningForm(
    const proto::Verification& item)
{
    proto::Verification signingForm(item);
    signingForm.clear_sig();

    return signingForm;
}

// static
std::string VerificationCredential::VerificationID(
    const proto::Verification& item)
{
    OTData hash;
    App::Me().Crypto().Hash().Digest(
        CryptoHash::HASH160,
        proto::ProtoAsData<proto::Verification>(item),
        hash);
    String ident = App::Me().Crypto().Util().Base58CheckEncode(hash);

    return std::string(ident.Get(), ident.GetLength());
}

VerificationCredential::VerificationCredential(
    CredentialSet& parent,
    const proto::Credential& credential)
        : ot_super(parent, credential)
{
    master_id_ = credential.childdata().masterid();
    data_.reset(new proto::VerificationSet(credential.verification()));
}

VerificationCredential::VerificationCredential(
    CredentialSet& parent,
    const NymParameters& nymParameters)
        : ot_super(parent, nymParameters)
{
    role_ = proto::CREDROLE_VERIFY;
    nym_id_ = parent.GetNymID();
    master_id_ = parent.GetMasterCredID();
    auto verificationSet = nymParameters.VerificationSet();
    if (verificationSet) {
        data_.reset(new proto::VerificationSet(*verificationSet));
    }
}

bool VerificationCredential::GetVerificationSet(
    std::unique_ptr<proto::VerificationSet>& verificationSet) const
{
    if (!data_) {
        return false;
    }

    verificationSet.reset(new proto::VerificationSet(*data_));

    return true;
}

serializedCredential VerificationCredential::asSerialized(
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

    *(serializedCredential->mutable_verification()) = *data_;

    return serializedCredential;
}

bool VerificationCredential::VerifyInternally() const
{
    // Perform common Credential verifications
    if (!ot_super::VerifyInternally()) {
        return false;
    }

    if (data_) {
        for (auto& nym: data_->internal().identity()) {
            for (auto& claim: nym.verification()) {
                bool valid = owner_backlink_->Verify(claim);
                if (!valid) {
                    otErr << __FUNCTION__ << ": invalid claim verification."
                          << std::endl;

                    return false;
                }
            }
        }
    }

    return true;
}

} // namespace opentxs
