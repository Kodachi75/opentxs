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

#ifndef OPENTXS_CORE_CONTRACT_SERVERCONTRACT_HPP
#define OPENTXS_CORE_CONTRACT_SERVERCONTRACT_HPP

#include "opentxs/core/Nym.hpp"
#include "opentxs/core/Proto.hpp"
#include "opentxs/core/contract/Signable.hpp"

#include <czmq.h>
#include <opentxs-proto/verify/VerifyContracts.hpp>

#include <cstdint>
#include <list>
#include <memory>
#include <string>
#include <tuple>

namespace opentxs
{

class OTData;
class String;

class ServerContract : public Signable
{
public:
    /** A server listen address */
    typedef std::tuple<
        proto::AddressType,
        proto::ProtocolVersion,
        std::string,    // hostname / address
        std::uint32_t,  // port
        std::uint32_t>  // version
            Endpoint;

private:
    typedef Signable ot_super;

    std::list<Endpoint> listen_params_;
    std::string name_;
    OTData transport_key_;

    Identifier GetID() const override;
    proto::ServerContract IDVersion() const;
    proto::ServerContract SigVersion() const;

    ServerContract() = delete;
    ServerContract(const ConstNym& nym);
    ServerContract(
        const ConstNym& nym,
        const proto::ServerContract& serialized);

public:
    static ServerContract* Create(
        const ConstNym& nym,
        const std::list<Endpoint>& endpoints,
        const std::string& terms,
        const std::string& name);
    static ServerContract* Factory(
        const ConstNym& nym,
        const proto::ServerContract& serialized);

    bool ConnectInfo(
        std::string& strHostname,
        uint32_t& nPort,
        const proto::AddressType& preferred = proto::ADDRESSTYPE_IPV4) const;
    const proto::ServerContract Contract() const;
    const proto::ServerContract PublicContract() const;
    bool Statistics(String& strContents) const;
    const unsigned char* PublicTransportKey() const;
    zcert_t* PrivateTransportKey() const;

    std::string Name() const override { return name_; }
    OTData Serialize() const override;
    bool Validate() const override;

    EXPORT ~ServerContract() = default;
};

} // namespace opentxs

#endif // OPENTXS_CORE_CONTRACT_SERVERCONTRACT_HPP
