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

#include "opentxs/core/app/Identity.hpp"

#include "opentxs/core/Log.hpp"
#include "opentxs/core/Nym.hpp"
#include "opentxs/core/String.hpp"
#include "opentxs/core/crypto/ContactCredential.hpp"
#include "opentxs/core/crypto/VerificationCredential.hpp"

namespace opentxs
{
//static
std::string Identity::ContactAttributeName(
    const proto::ContactItemAttribute type,
    std::string lang)
{
    return proto::TranslateItemAttributes(type, lang);
}

//static
std::set<proto::ContactSectionName> Identity::ContactSectionList(
    const std::uint32_t version)
{
    std::set<proto::ContactSectionName> sections;

    for (auto& it: proto::AllowedSectionNames.at(version)) {
        sections.insert(it);
    }

    return sections;
}

//static
std::string Identity::ContactSectionName(
    const proto::ContactSectionName section,
    std::string lang)
{
    return proto::TranslateSectionName(section, lang);
}

//static
std::set<proto::ContactItemType> Identity::ContactSectionTypeList(
    const proto::ContactSectionName section,
    const std::uint32_t version)
{
    proto::ContactSectionVersion contactVersion{version, section};
    std::set<proto::ContactItemType> sectionTypes;

    for (auto& it: proto::AllowedItemTypes.at(contactVersion)) {
        sectionTypes.insert(it);
    }

    return sectionTypes;
}

//static
std::string Identity::ContactTypeName(
    const proto::ContactItemType type,
    std::string lang)
{
    return proto::TranslateItemType(type, lang);
}

//static
proto::ContactItemType Identity::ReciprocalRelationship(
    const proto::ContactItemType relationship)
{
    return static_cast<proto::ContactItemType>(
        proto::ReciprocalRelationship(relationship));
}

bool Identity::AddClaim(
    Nym& toNym,
    const Claim claim) const
{
    std::unique_ptr<proto::ContactData> revised;
    auto existing = toNym.ContactData();

    if (existing) {
        revised.reset(new proto::ContactData(*existing));
    } else {
        revised = InitializeContactData();
    }

    AddClaimToSection(*revised, claim);

    return toNym.SetContactData(*revised);
}

void Identity::AddClaimToSection(
    proto::ContactData& data,
    const Claim& claim) const
{
    const auto sectionType =
        static_cast<proto::ContactSectionName>(std::get<1>(claim));
    const auto itemType =
        static_cast<proto::ContactItemType>(std::get<2>(claim));
    const auto value = std::get<3>(claim);
    const auto start = std::get<4>(claim);
    const auto end = std::get<5>(claim);

    auto section = GetOrCreateSection(
        data,
        sectionType);
    const bool primary = ClaimIsPrimary(claim);

    if (primary) {
        ResetPrimary(section, itemType);
    }

    auto& item = GetOrCreateClaim(
        section,
        itemType,
        value,
        start,
        end);

    SetAttributesOnClaim(item, claim);
}

bool Identity::AddInternalVerification(
    bool& changed,
    proto::VerificationSet& verifications,
    const Nym& onNym,
    const std::string& claimantNymID,
    const std::string& claimID,
    const ClaimPolarity polarity,
    const int64_t start,
    const int64_t end,
    const OTPasswordData* pPWData) const
{
    auto& internal = GetOrCreateInternalGroup(
        verifications,
        verifications.version());
    auto& identity = GetOrCreateVerificationIdentity(
        internal,
        claimantNymID,
        verifications.version());

    // check for an exact match
    const bool exists = HaveVerification(
        identity,
        claimID,
        polarity,
        start,
        end);

    if (!exists) {
        // removes all conflicting verifications
        DeleteVerification(changed, identity, claimID, start, end);

        auto& newVerification = *identity.add_verification();
        newVerification.set_version(identity.version());
        newVerification.set_claim(claimID);

        if (ClaimPolarity::POSITIVE == polarity) {
            newVerification.set_valid(true);
        } else {
            newVerification.set_valid(false);
        }

        newVerification.set_start(start);
        newVerification.set_end(end);

        changed = true;

        return onNym.Sign(newVerification, pPWData);
    }

    return true;
}

std::unique_ptr<proto::ContactData> Identity::Claims(const Nym& fromNym) const
{
    auto data = fromNym.ContactData();
    String nymID = fromNym.ID();

    PopulateClaimIDs(*data, nymID.Get());

    return data;
}

bool Identity::ClaimIsPrimary(const Claim& claim) const
{
    bool primary = false;

    for (auto& attribute: std::get<6>(claim)) {
        if (proto::CITEMATTR_PRIMARY == attribute) {
            primary = true;
        }
    }

    return primary;
}

// Because we're building with protobuf-lite, we don't have library
// support for deleting items from protobuf repeated fields.
// Thus we delete by making a copy which excludes the item to be
// deleted.
void Identity::ClearPrimaryAttribute(proto::ContactItem& claim) const
{
    proto::ContactItem revised;
    revised.set_version(claim.version());
    revised.set_type(claim.type());
    revised.set_start(claim.start());
    revised.set_end(claim.end());
    bool changed = false;

    for (auto& attribute : claim.attribute()) {
        if (proto::CITEMATTR_PRIMARY == attribute) {
            changed = true;
        } else {
            revised.add_attribute(
                static_cast<proto::ContactItemAttribute>(attribute));
        }
    }

    if (changed) {
        claim = revised;
    }
}

// Because we're building with protobuf-lite, we don't have library
// support for deleting items from protobuf repeated fields.
// Thus we delete by making a copy which excludes the item to be
// deleted.
bool Identity::DeleteClaim(Nym& onNym, const std::string& claimID) const
{
    String nymID;
    onNym.GetIdentifier(nymID);

    auto data = onNym.ContactData();
    proto::ContactData newData;
    newData.set_version(data->version());

    for (auto& section : data->section()) {
        auto newSection = newData.add_section();

        newSection->set_version(section.version());
        newSection->set_name(section.name());

        for (auto& item: section.item()) {
            auto claim = ContactCredential::asClaim(
                nymID.Get(),
                section.name(),
                item);

            if (std::get<0>(claim) != claimID) {
                *(newSection->add_item()) = item;
            }
        }
    }

    return onNym.SetContactData(newData);
}

// Because we're building with protobuf-lite, we don't have library
// support for deleting items from protobuf repeated fields.
// Thus we delete by making a copy which excludes the item to be
// deleted.
void Identity::DeleteVerification(
    bool& changed,
    proto::VerificationIdentity& identity,
    const std::string& claimID,
    const int64_t start,
    const int64_t end) const
{
    proto::VerificationIdentity newData;
    newData.set_version(identity.version());
    newData.set_nym(identity.nym());

    for (auto& verification: identity.verification()) {
        //TODO:: Handle all of these cases correctly:
        // https://en.wikipedia.org/wiki/Allen's_interval_algebra#Relations
        if (!MatchVerification(verification, claimID, start, end)) {
            auto& it = *newData.add_verification();
            it = verification;
        } else {
            changed = true;
        }
    }

    if (changed) {
        identity = newData;
    }
}

proto::ContactItem& Identity::GetOrCreateClaim(
    proto::ContactSection& section,
    const proto::ContactItemType type,
    const std::string& value,
    const std::int64_t start,
    const std::int64_t end) const
{
    for (auto& claim : *section.mutable_item()) {
        if ((type == claim.type()) &&
            (value == claim.value()) &&
            (start <= claim.start()) &&
            (end >= claim.end())) {
                claim.set_start(start);
                claim.set_end(end);

                return claim;
        }
    }

    auto& newClaim = *section.add_item();
    InitializeContactItem(newClaim, type, value, start, end);

    return newClaim;
}

proto::VerificationGroup& Identity::GetOrCreateInternalGroup(
    proto::VerificationSet& verificationSet,
    const std::uint32_t version) const
{
    const bool existing = verificationSet.has_internal();
    auto& output = *verificationSet.mutable_internal();

    if (!existing) {
        output.set_version(version);
    }

    return output;
}

proto::ContactSection& Identity::GetOrCreateSection(
    proto::ContactData& data,
    proto::ContactSectionName section,
    const std::uint32_t version) const
{
    for (auto& it : *data.mutable_section()) {
        if (it.name() == section) {

            return it;
        }
    }

    auto& newSection = *data.add_section();
    InitializeContactSection(newSection, section, version);

    return newSection;
}

proto::VerificationIdentity& Identity::GetOrCreateVerificationIdentity(
    proto::VerificationGroup& verificationGroup,
    const std::string& nym,
    const std::uint32_t version) const
{
    for (auto& identity : *verificationGroup.mutable_identity()) {
        if (identity.nym() == nym) {

            return identity;
        }
    }

    //We didn't find an existing item, so create a new one
    auto& identity = *verificationGroup.add_identity();
    identity.set_version(version);
    identity.set_nym(nym);

    return identity;
}

bool Identity::HaveVerification(
    proto::VerificationIdentity& identity,
    const std::string& claimID,
    const ClaimPolarity polarity,
    const int64_t start,
    const int64_t end) const
{
    bool match = false;

    if (ClaimPolarity::NEUTRAL != polarity) {
        bool valid = false;

        if (ClaimPolarity::POSITIVE == polarity) { valid = true; }

        for (auto& verification: identity.verification()) {
            if (verification.claim() != claimID) { break; }
            if (verification.valid() != valid) { break; }
            if (verification.start() != start) { break; }
            if (verification.end() != end) { break; }

            match = true;
        }
    }

    return match;
}

std::unique_ptr<proto::ContactData> Identity::InitializeContactData(
    const std::uint32_t version) const
{
    std::unique_ptr<proto::ContactData> output(new proto::ContactData);
    output->set_version(version);

    return output;
}

void Identity::InitializeContactItem(
    proto::ContactItem& item,
    const proto::ContactItemType type,
    const std::string& value,
    const std::int64_t start,
    const std::int64_t end) const
{
    item.set_type(type);
    item.set_value(value);
    item.set_start(start);
    item.set_end(end);
}

void Identity::InitializeContactSection(
    proto::ContactSection& section,
    const proto::ContactSectionName name,
    const std::uint32_t version) const
{
    section.set_version(version);
    section.set_name(name);
}

std::unique_ptr<proto::VerificationSet> Identity::InitializeVerificationSet(
    const std::uint32_t version) const
{
    std::unique_ptr<proto::VerificationSet> output(new proto::VerificationSet);

    if (output) {
        output->set_version(version);
    } else {
        otErr << __FUNCTION__ << ": Failed to instantiate verification set."
              << std::endl;
    }

    return output;
}

bool Identity::MatchVerification(
    const proto::Verification& item,
    const std::string& claimID,
    const int64_t start,
    const int64_t end) const
{
    // different claim
    if (item.claim() != claimID) { return false; }

    if ((item.start() == start) && (item.end() == end)) { return true; }

    // time range for claim falls outside given interval
    if (item.start() >= end) { return false; }
    if (item.end() <= start) { return false; }

    return true;
}

void Identity::PopulateClaimIDs(
    proto::ContactData& data,
    const std::string& nym) const
{
    for (auto& section : *data.mutable_section()) {
        for (auto& item : *section.mutable_item()) {
            const auto id =
                ContactCredential::ClaimID(nym, section.name(), item);
            item.set_id(id);
        }
    }
}

void Identity::PopulateVerificationIDs(proto::VerificationGroup& group) const
{
    for (auto& identity : *group.mutable_identity()) {
        for (auto& item : *identity.mutable_verification()) {
            const auto id = VerificationCredential::VerificationID(item);
            item.set_id(id);
        }
    }
}

bool Identity::RemoveInternalVerification(
    bool& changed,
    proto::VerificationSet& verifications,
    const std::string& claimantNymID,
    const std::string& claimID,
    const int64_t start,
    const int64_t end) const
{
    if (verifications.has_internal()) {
        auto& internalGroup = *verifications.mutable_internal();

        for (auto& identity : *internalGroup.mutable_identity()) {
            if (claimantNymID == identity.nym()) {
                DeleteVerification(changed, identity, claimID, start, end);
            }
        }
        // no internal verifications for the claimant nym means nothing to delete
    } // else: no internal verifications to delete means nothing to delete

    return true;
}

void Identity::ResetPrimary(
    proto::ContactSection& section,
    const proto::ContactItemType& type) const
{
    for (auto& item: *section.mutable_item()) {
        if (type == item.type()) {
            ClearPrimaryAttribute(item);
        }
    }
}

void Identity::SetAttributesOnClaim(
    proto::ContactItem& item,
    const Claim& claim) const
{
    item.clear_attribute();

    for (auto& attribute: std::get<6>(claim)) {
        item.add_attribute(
            static_cast<proto::ContactItemAttribute>(attribute));
    }
}

std::unique_ptr<proto::VerificationSet> Identity::Verifications(
    const Nym& onNym) const
{
    auto output = onNym.VerificationSet();

    if (output) {
        if (output->has_internal()) {
            auto& group = *output->mutable_internal();
            PopulateVerificationIDs(group);
        }

        if (output->has_external()) {
            auto& group = *output->mutable_external();
            PopulateVerificationIDs(group);
        }
    }

    return output;
}

std::unique_ptr<proto::VerificationSet> Identity::Verify(
    Nym& onNym,
    bool& changed,
    const std::string& claimantNymID,
    const std::string& claimID,
    const ClaimPolarity polarity,
    const int64_t start,
    const int64_t end,
    const OTPasswordData* pPWData) const
{
    changed = false;
    std::unique_ptr<proto::VerificationSet> revised;
    auto existing = onNym.VerificationSet();

    if (existing) {
        revised.reset(new proto::VerificationSet(*existing));
    } else {
        changed = true;
        revised = InitializeVerificationSet();
    }

    if (!revised) { return revised; }

    bool finished = false;

    if (ClaimPolarity::NEUTRAL == polarity) {
        finished = RemoveInternalVerification(
            changed,
            *revised,
            claimantNymID,
            claimID,
            start,
            end);
    } else {
        finished = AddInternalVerification(
            changed,
            *revised,
            onNym,
            claimantNymID,
            claimID,
            polarity,
            start,
            end,
            pPWData);
    }

    if (finished) {
        if (changed) {
            const bool updated = onNym.SetVerificationSet(*revised);

            if (updated) {
                return revised;
            } else {
                otErr << __FUNCTION__ << ": Failed to update verification set."
                    << std::endl;
            }
        } else {
            return revised;
        }
    } else {
        otErr << __FUNCTION__ << ": Failed to add internal verification."
              << std::endl;
    }

    return nullptr;
}
} // namespace opentxs
