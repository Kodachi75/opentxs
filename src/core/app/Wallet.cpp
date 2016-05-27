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

#include "opentxs/core/app/Wallet.hpp"

#include <thread>

#include "opentxs/core/app/App.hpp"
#include "opentxs/core/Log.hpp"

namespace opentxs
{
ConstNym Wallet::Nym(
    const Identifier& id,
    const std::chrono::milliseconds& timeout)
{
    const std::string nym = String(id).Get();
    std::unique_lock<std::mutex> mapLock(nym_map_lock_);
    bool inMap = (nym_map_.find(nym) != nym_map_.end());
    bool valid = false;

    if (!inMap) {
        std::shared_ptr<proto::CredentialIndex> serialized;

        std::string alias;
        bool loaded = App::Me().DB().Load(nym, serialized, alias, true);

        if (loaded) {
            auto& pNym = nym_map_[nym].second;
            pNym.reset(new class Nym(id));
            if (pNym) {
                if (pNym->LoadCredentialIndex(*serialized)) {
                    valid = pNym->VerifyPseudonym();
                    pNym->SetAlias(alias);
                }
            }
        } else {
            App::Me().DHT().GetPublicNym(nym);

            if (timeout > std::chrono::milliseconds(0)) {
                mapLock.unlock();
                auto start = std::chrono::high_resolution_clock::now();
                auto end = start + timeout;
                const auto interval = std::chrono::milliseconds(100);

                while (std::chrono::high_resolution_clock::now() < end) {
                    std::this_thread::sleep_for(interval);
                    mapLock.lock();
                    bool found = (nym_map_.find(nym) != nym_map_.end());
                    mapLock.unlock();

                    if (found) { break; }
                }

                return Nym(id); // timeout of zero prevents infinite recursion
            }
        }
    } else {
        auto& pNym = nym_map_[nym].second;
        if (pNym) {
            valid = pNym->VerifyPseudonym();
        }
    }

    if (valid) {
        return nym_map_[nym].second;
    }

    return nullptr;
}

ConstNym Wallet::Nym(
    const proto::CredentialIndex& publicNym)
{
    std::string nym = publicNym.nymid();

    auto existing = Nym(nym);

    if (existing) {
        if (existing->Revision() >= publicNym.revision()) {

            return existing;
        }
    }
    existing.reset();

    std::unique_ptr<class Nym>
        candidate(new class Nym(Identifier(nym)));

    if (candidate) {
        candidate->LoadCredentialIndex(publicNym);

        if (candidate->VerifyPseudonym()) {
            candidate->WriteCredentials();
            candidate->SaveCredentialIDs();
            SetNymAlias(nym, candidate->Alias());
            std::unique_lock<std::mutex> mapLock(nym_map_lock_);
            nym_map_[nym].second.reset(candidate.release());
            mapLock.unlock();
        }
    }

    return Nym(nym);
}

bool Wallet::RemoveServer(const Identifier& id)
{
    std::string server(String(id).Get());
    std::unique_lock<std::mutex> mapLock(server_map_lock_);
    auto deleted = server_map_.erase(server);

    if (0 != deleted) {
        return App::Me().DB().RemoveServer(server);
    }

    return false;
}

bool Wallet::RemoveUnitDefinition(const Identifier& id)
{
    std::string unit(String(id).Get());
    std::unique_lock<std::mutex> mapLock(unit_map_lock_);
    auto deleted = unit_map_.erase(unit);

    if (0 != deleted) {
        return App::Me().DB().RemoveUnitDefinition(unit);
    }

    return false;
}

ConstServerContract Wallet::Server(
    const Identifier& id,
    const std::chrono::milliseconds& timeout)
{
    const String strID(id);
    const std::string server = strID.Get();
    std::unique_lock<std::mutex> mapLock(server_map_lock_);
    bool inMap = (server_map_.find(server) != server_map_.end());
    bool valid = false;

    if (!inMap) {
        std::shared_ptr<proto::ServerContract> serialized;

        std::string alias;
        bool loaded = App::Me().DB().Load(server, serialized, alias, true);

        if (loaded) {
            auto nym = Nym(serialized->nymid());

            if (!nym && serialized->has_publicnym()) {
                nym = Nym(serialized->publicnym());
            }

            if (nym) {
                auto& pServer = server_map_[server];
                pServer.reset(
                    ServerContract::Factory(nym, *serialized));

                if (pServer) {
                    valid = true; // Factory() performs validation
                    pServer->SetAlias(alias);
                }
            }
        } else {
            App::Me().DHT().GetServerContract(server);

            if (timeout > std::chrono::milliseconds(0)) {
                mapLock.unlock();
                auto start = std::chrono::high_resolution_clock::now();
                auto end = start + timeout;
                const auto interval = std::chrono::milliseconds(100);

                while (std::chrono::high_resolution_clock::now() < end) {
                    std::this_thread::sleep_for(interval);
                    mapLock.lock();
                    bool found = (server_map_.find(server) != server_map_.end());
                    mapLock.unlock();

                    if (found) { break; }
                }

                return Server(id); // timeout of zero prevents infinite recursion
            }
        }
    } else {
        auto& pServer = server_map_[server];
        if (pServer) {
            valid = pServer->Validate();
        }
    }

    if (valid) {
        return server_map_[server];
    }

    return nullptr;
}

ConstServerContract Wallet::Server(
    std::unique_ptr<class ServerContract>& contract)
{
    std::string server = String(contract->ID()).Get();

    if (contract) {
        if (contract->Validate()) {
            if (App::Me().DB().Store(
                contract->Contract(),
                contract->Alias())) {
                    std::unique_lock<std::mutex> mapLock(server_map_lock_);
                    server_map_[server].reset(contract.release());
                    mapLock.unlock();
            }
        }
    }

    return Server(server);
}

ConstServerContract Wallet::Server(
    const proto::ServerContract& contract)
{
    std::string server = contract.id();
    auto nym = Nym(contract.nymid());

    if (!nym && contract.has_publicnym()) {
        nym = Nym(contract.publicnym());
    }

    if (nym) {
        std::unique_ptr<ServerContract>
            candidate(ServerContract::Factory(nym, contract));

        if (candidate) {
            if (candidate->Validate()) {
                if (App::Me().DB().Store(
                    candidate->Contract(),
                    candidate->Alias())) {
                        std::unique_lock<std::mutex> mapLock(server_map_lock_);
                        server_map_[server].reset(candidate.release());
                        mapLock.unlock();
                }
            }
        }
    }

    return Server(server);
}

ConstServerContract Wallet::Server(
    const std::string& nymid,
    const std::string& name,
    const std::string& terms,
    const std::list<ServerContract::Endpoint>& endpoints)
{
    std::string server;

    auto nym = Nym(nymid);

    if (nym) {
        std::unique_ptr<ServerContract> contract;
        contract.reset(ServerContract::Create(
            nym,
            endpoints,
            terms,
            name));

        if (contract) {

            return (Server(contract));
        } else {
            otErr << __FUNCTION__ << ": Error: failed to create contract."
                  << std::endl;
        }
    } else {
        otErr << __FUNCTION__ << ": Error: nym does not exist." << std::endl;
    }

    return Server(server);
}

Storage::ObjectList Wallet::ServerList()
{
    return App::Me().DB().ServerList();
}

bool Wallet::SetNymAlias(const Identifier& id, const std::string alias)
{
    return App::Me().DB().SetNymAlias(String(id).Get(), alias);
}

bool Wallet::SetServerAlias(const Identifier& id, const std::string alias)
{
    return App::Me().DB().SetServerAlias(String(id).Get(), alias);
}

bool Wallet::SetUnitDefinitionAlias(
    const Identifier& id,
    const std::string alias)
{
    return App::Me().DB().SetUnitDefinitionAlias(String(id).Get(), alias);
}

Storage::ObjectList Wallet::UnitDefinitionList()
{
    return App::Me().DB().UnitDefinitionList();
}

ConstUnitDefinition Wallet::UnitDefinition(
    const Identifier& id,
    const std::chrono::milliseconds& timeout)
{
    const String strID(id);
    const std::string unit = strID.Get();
    std::unique_lock<std::mutex> mapLock(unit_map_lock_);
    bool inMap = (unit_map_.find(unit) != unit_map_.end());
    bool valid = false;

    if (!inMap) {
        std::shared_ptr<proto::UnitDefinition> serialized;

        std::string alias;
        bool loaded = App::Me().DB().Load(unit, serialized, alias, true);

        if (loaded) {
            auto nym = Nym(serialized->nymid());

            if (!nym && serialized->has_publicnym()) {
                nym = Nym(serialized->publicnym());
            }

            if (nym) {
                auto& pUnit = unit_map_[unit];
                pUnit.reset(UnitDefinition::Factory(nym, *serialized));

                if (pUnit) {
                    valid = true; // Factory() performs validation
                    pUnit->SetAlias(alias);
                }
            }
        } else {
            App::Me().DHT().GetUnitDefinition(unit);

            if (timeout > std::chrono::milliseconds(0)) {
                mapLock.unlock();
                auto start = std::chrono::high_resolution_clock::now();
                auto end = start + timeout;
                const auto interval = std::chrono::milliseconds(100);

                while (std::chrono::high_resolution_clock::now() < end) {
                    std::this_thread::sleep_for(interval);
                    mapLock.lock();
                    bool found = (unit_map_.find(unit) != unit_map_.end());
                    mapLock.unlock();

                    if (found) { break; }
                }

                return UnitDefinition(id); // timeout of zero prevents
                                           // infinite recursion
            }
        }
    } else {
        auto& pUnit = unit_map_[unit];
        if (pUnit) {
            valid = pUnit->Validate();
        }
    }

    if (valid) {
        return unit_map_[unit];
    }

    return nullptr;
}

ConstUnitDefinition Wallet::UnitDefinition(
    std::unique_ptr<class UnitDefinition>& contract)
{
    std::string unit = String(contract->ID()).Get();

    if (contract) {
        if (contract->Validate()) {
            if (App::Me().DB().Store(
                contract->Contract(),
                contract->Alias())) {
                    std::unique_lock<std::mutex> mapLock(unit_map_lock_);
                    unit_map_[unit].reset(contract.release());
                    mapLock.unlock();
            }
        }
    }

    return UnitDefinition(unit);
}

ConstUnitDefinition Wallet::UnitDefinition(
    const proto::UnitDefinition& contract)
{
    std::string unit = contract.id();
    auto nym = Nym(contract.nymid());

    if (!nym && contract.has_publicnym()) {
        nym = Nym(contract.publicnym());
    }

    if (nym) {
        std::unique_ptr<class UnitDefinition>
            candidate(UnitDefinition::Factory(nym, contract));

        if (candidate) {
            if (candidate->Validate()) {
                if (App::Me().DB().Store(
                    candidate->Contract(),
                    candidate->Alias())) {
                        std::unique_lock<std::mutex> mapLock(unit_map_lock_);
                        unit_map_[unit].reset(candidate.release());
                        mapLock.unlock();
                }
            }
        }
    }

    return UnitDefinition(unit);
}

ConstUnitDefinition Wallet::UnitDefinition(
    const std::string& nymid,
    const std::string& shortname,
    const std::string& name,
    const std::string& symbol,
    const std::string& terms,
    const std::string& tla,
    const uint32_t& power,
    const std::string& fraction)
{
    std::string unit;

    auto nym = Nym(nymid);

    if (nym) {
        std::unique_ptr<class UnitDefinition> contract;
        contract.reset(UnitDefinition::Create(
            nym,
            shortname,
            name,
            symbol,
            terms,
            tla,
            power,
            fraction));
        if (contract) {

            return (UnitDefinition(contract));
        } else {
            otErr << __FUNCTION__ << ": Error: failed to create contract."
                  << std::endl;
        }
    } else {
        otErr << __FUNCTION__ << ": Error: nym does not exist." << std::endl;
    }

    return UnitDefinition(unit);
}

ConstUnitDefinition Wallet::UnitDefinition(
    const std::string& nymid,
    const std::string& shortname,
    const std::string& name,
    const std::string& symbol,
    const std::string& terms)
{
    std::string unit;

    auto nym = Nym(nymid);

    if (nym) {
        std::unique_ptr<class UnitDefinition> contract;
        contract.reset(UnitDefinition::Create(
            nym,
            shortname,
            name,
            symbol,
            terms));
        if (contract) {

            return (UnitDefinition(contract));
        } else {
            otErr << __FUNCTION__ << ": Error: failed to create contract."
                  << std::endl;
        }
    } else {
        otErr << __FUNCTION__ << ": Error: nym does not exist." << std::endl;
    }

    return UnitDefinition(unit);
}

} // namespace opentxs
