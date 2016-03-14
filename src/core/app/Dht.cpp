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

#include <opentxs/core/app/Dht.hpp>

#include <opentxs/core/Log.hpp>
#include <opentxs/core/OTData.hpp>
#include <opentxs/core/String.hpp>
#include <opentxs/core/app/App.hpp>
#include <opentxs/core/contract/ServerContract.hpp>
#include <opentxs/core/contract/UnitDefinition.hpp>
#include <opentxs/core/crypto/Credential.hpp>

namespace opentxs
{

Dht* Dht::instance_ = nullptr;

Dht::Dht(DhtConfig& config)
    : config_(config)
{
    Init();
}

void Dht::Init()
{
#ifdef OT_DHT
    node_ = &OpenDHT::It(config_);
#endif
}

Dht* Dht::It(DhtConfig& config)
{
    if (nullptr == instance_)
    {
        instance_ = new Dht(config);
    }

    return instance_;
}

void Dht::Insert(
    __attribute__((unused)) const std::string& key,
    __attribute__((unused)) const std::string& value)
{
    #ifdef OT_DHT
    OT_ASSERT(nullptr != node_);

    node_->Insert(key, value);
    #endif
}

void Dht::Insert(__attribute__((unused)) const serializedCredentialIndex& nym)
{
#ifdef OT_DHT
    OT_ASSERT(nullptr != node_);

    node_->Insert(
        nym.nymid(),
        proto::ProtoAsString(nym));
#endif
}

void Dht::Insert(__attribute__((unused)) const proto::ServerContract& contract)
{
#ifdef OT_DHT
    OT_ASSERT(nullptr != node_);

    node_->Insert(
        contract.id(),
        proto::ProtoAsString(contract));
#endif
}

void Dht::Insert(__attribute__((unused)) const proto::UnitDefinition& contract)
{
#ifdef OT_DHT
    OT_ASSERT(nullptr != node_);

    node_->Insert(
        contract.id(),
        proto::ProtoAsString(contract));
#endif
}

void Dht::GetPublicNym(
    __attribute__((unused)) const std::string& key)
{
#ifdef OT_DHT
    OT_ASSERT(nullptr != node_);

    auto it = callback_map_.find(Dht::Callback::PUBLIC_NYM);
    bool haveCB = (it != callback_map_.end());
    NotifyCB notifyCB;

    if (haveCB) {
        notifyCB = it->second;
    }

    dht::Dht::GetCallback gcb(
        [notifyCB](const OpenDHT::Results& values) -> bool {
            return ProcessPublicNym(values, notifyCB);});

    node_->Retrieve(key, gcb);
#endif
}

void Dht::GetServerContract(
    __attribute__((unused)) const std::string& key)
{
#ifdef OT_DHT
    OT_ASSERT(nullptr != node_);

    auto it = callback_map_.find(Dht::Callback::SERVER_CONTRACT);
    bool haveCB = (it != callback_map_.end());
    NotifyCB notifyCB;

    if (haveCB) {
        notifyCB = it->second;
    }

    dht::Dht::GetCallback gcb(
        [notifyCB](const OpenDHT::Results& values) -> bool {
            return ProcessServerContract(values, notifyCB);});

    node_->Retrieve(key, gcb);
#endif
}

void Dht::GetUnitDefinition(
    __attribute__((unused)) const std::string& key)
{
#ifdef OT_DHT
    OT_ASSERT(nullptr != node_);

    auto it = callback_map_.find(Dht::Callback::ASSET_CONTRACT);
    bool haveCB = (it != callback_map_.end());
    NotifyCB notifyCB;

    if (haveCB) {
        notifyCB = it->second;
    }

    dht::Dht::GetCallback gcb(
        [notifyCB](const OpenDHT::Results& values) -> bool {
            return ProcessUnitDefinition(values, notifyCB);});

    node_->Retrieve(key, gcb);
#endif
}

#ifdef OT_DHT
bool Dht::ProcessPublicNym(
    const OpenDHT::Results& values,
    NotifyCB notifyCB)
{
    std::string theresult;
    bool foundData = false;
    bool foundValid = false;

    for (const auto & it: values)
    {
        auto & ptr = *it;
        std::string data(ptr.data.begin(), ptr.data.end());
        foundData = data.size() > 0;

        if (0 == ptr.user_type.size()) { continue; }

        std::string nymID(ptr.user_type);

        if (0 == data.size()) { continue; }

        auto publicNym =
            proto::DataToProto<proto::CredentialIndex>
            (OTData(data.c_str(), data.size()));

        if (nymID != publicNym.nymid()) { continue; }

        auto existing  = App::Me().Contract().Nym(nymID);

        if (existing) {
            if (existing->Revision() >= publicNym.revision()) {
                continue;
            }
        }

        auto saved = App::Me().Contract().Nym(publicNym);

        if (!saved) { continue; }

        foundValid = true;
        otLog3 << "Saved nym: " << nymID << std::endl;

        if (notifyCB) {
            notifyCB(nymID);
        }
    }

    if (!foundValid) {
        otErr << __FUNCTION__ << "Found results, but none are valid."
              << std::endl;
    }

    if (!foundData) {
        otErr << __FUNCTION__ << "All results are empty" << std::endl;
    }

    return foundData;
}

bool Dht::ProcessServerContract(
    const OpenDHT::Results& values,
    NotifyCB notifyCB)
{
    std::string theresult;
    bool foundData = false;
    bool foundValid = false;

    for (const auto & it: values)
    {
        auto & ptr = *it;
        std::string data(ptr.data.begin(), ptr.data.end());
        foundData = data.size() > 0;

        if (0 == ptr.user_type.size()) { continue; }

        Identifier contractID(ptr.user_type);

        if (0 == data.size()) { continue; }

        auto contract =
            proto::DataToProto<proto::ServerContract>
                (OTData(data.c_str(), data.size()));

        auto saved = App::Me().Contract().Server(contract);

        if (!saved) { continue; }

        otLog3 << "Saved contract: " << ptr.user_type << std::endl;
        foundValid = true;

        if (notifyCB) {
            notifyCB(ptr.user_type);
        }

        break; // We only need the first valid result
    }

    if (!foundValid) {
        otErr << __FUNCTION__ << "Found results, but none are valid."
              << std::endl;
    }

    if (!foundData) {
        otErr << __FUNCTION__ << "All results are empty" << std::endl;
    }

    return foundData;
}

bool Dht::ProcessUnitDefinition(
    const OpenDHT::Results& values,
    NotifyCB notifyCB)
{
    std::string theresult;
    bool foundData = false;
    bool foundValid = false;

    for (const auto & it: values)
    {
        auto & ptr = *it;
        std::string data(ptr.data.begin(), ptr.data.end());
        foundData = data.size() > 0;

        if (0 == ptr.user_type.size()) { continue; }

        Identifier contractID(ptr.user_type);

        if (0 == data.size()) { continue; }

        auto contract =
            proto::DataToProto<proto::UnitDefinition>
                (OTData(data.c_str(), data.size()));

        auto saved = App::Me().Contract().UnitDefinition(contract);

        if (!saved) { continue; }

        otLog3 << "Saved unit definition: " << ptr.user_type << std::endl;
        foundValid = true;

        if (notifyCB) {
            notifyCB(ptr.user_type);
        }

        break; // We only need the first valid result
    }

    if (!foundValid) {
        otErr << __FUNCTION__ << "Found results, but none are valid."
              << std::endl;
    }

    if (!foundData) {
        otErr << __FUNCTION__ << "All results are empty" << std::endl;
    }

    return foundData;
}
#endif

void Dht::Cleanup()
{
#ifdef OT_DHT
    if (nullptr != node_)
        delete node_;
    node_ = nullptr;
    instance_ = nullptr;
#endif
}

void Dht::RegisterCallbacks(const CallbackMap& callbacks)
{
    callback_map_ = callbacks;
}

Dht::~Dht()
{
    Cleanup();
}

} // namespace opentxs
