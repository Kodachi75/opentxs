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

#ifndef OPENTXS_CORE_APP_DHT_HPP
#define OPENTXS_CORE_APP_DHT_HPP

#include <string>

#include <opentxs-proto/verify/VerifyContracts.hpp>

#include <opentxs/core/Proto.hpp>
#include <opentxs/network/DhtConfig.hpp>
#include <opentxs/network/OpenDHT.hpp>

namespace opentxs
{

class App;
class Credential;
class ServerContract;
class UnitDefinition;

//High level interface to OpenDHT. Supports opentxs types.
class Dht
{
public:
    enum class Callback : uint8_t {
        SERVER_CONTRACT = 0,
        ASSET_CONTRACT = 1,
        PUBLIC_NYM = 2
    };

    typedef std::function<void(const std::string)> NotifyCB;
    typedef std::map<Callback, NotifyCB> CallbackMap;

private:
    friend class App;

    static Dht* instance_;

    CallbackMap callback_map_;
    DhtConfig config_;
#ifdef OT_DHT
    OpenDHT* node_ = nullptr;
#endif

    static Dht* It(DhtConfig& config);

#ifdef OT_DHT
    static bool ProcessPublicNym(
        const OpenDHT::Results& values,
        NotifyCB notifyCB);
    static bool ProcessServerContract(
        const OpenDHT::Results& values,
        NotifyCB notifyCB);
    static bool ProcessUnitDefinition(
        const OpenDHT::Results& values,
        NotifyCB notifyCB);
#endif

    Dht(DhtConfig& config);
    Dht() = delete;
    Dht(const Dht&) = delete;
    Dht& operator=(const Dht&) = delete;
    void Init();

public:
    EXPORT void Insert(
        const std::string& key,
        const std::string& value);
    EXPORT void Insert(const proto::CredentialIndex& nym);
    EXPORT void Insert(const proto::ServerContract& contract);
    EXPORT void Insert(const proto::UnitDefinition& contract);
    EXPORT void GetPublicNym(const std::string& key);
    EXPORT void GetServerContract(const std::string& key);
    EXPORT void GetUnitDefinition(const std::string& key);
    EXPORT void RegisterCallbacks(const CallbackMap& callbacks);

    void Cleanup();
    ~Dht();
};

}  // namespace opentxs
#endif // OPENTXS_CORE_APP_DHT_HPP
