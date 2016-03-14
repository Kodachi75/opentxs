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

#ifndef OPENTXS_CLIENT_OTSERVERCONNECTION_HPP
#define OPENTXS_CLIENT_OTSERVERCONNECTION_HPP

#include <memory>
#include <string>
#include <opentxs/core/String.hpp>

// forward declare zsock_t
typedef struct _zsock_t zsock_t;

namespace opentxs
{

class OTClient;
class Identifier;
class Nym;
class ServerContract;
class OTEnvelope;
class Message;

class OTServerConnection
{
public:
    OTServerConnection(OTClient* theClient, const std::string& endpoint,
                       const unsigned char* transportKey);
    ~OTServerConnection();

    bool GetNotaryID(Identifier& theID) const;

    inline Nym* GetNym() const
    {
        return m_pNym;
    }

    inline const ServerContract* GetServerContract() const
    {
        return m_pServerContract;
    }

    void OnServerResponseToGetRequestNumber(int64_t lNewRequestNumber) const;

    void send(const ServerContract* pServerContract, Nym* pNym,
              const Message& theMessage);

    bool resetSocket();

    static int getLinger();
    static int getSendTimeout();
    static int getRecvTimeout();

    static void setLinger(int nIn);
    static void setSendTimeout(int nIn);
    static void setRecvTimeout(int nIn);

    static bool networkFailure();    // This returns s_bNetworkFailure.

private:
    bool send(const String&);
    bool receive(std::string& reply);

private:
    zsock_t* socket_zmq;
    Nym* m_pNym;
    ServerContract const * m_pServerContract = nullptr;
    OTClient* m_pClient;

    std::string m_endpoint;

    static int s_linger;
    static int s_send_timeout;
    static int s_recv_timeout;
    // -----------------------------
    // Used to signal network failure.
    static bool s_bNetworkFailure;
};

} // namespace opentxs

#endif // OPENTXS_CLIENT_OTSERVERCONNECTION_HPP
