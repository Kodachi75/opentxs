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

#ifndef OPENTXS_SERVER_OTSERVER_HPP
#define OPENTXS_SERVER_OTSERVER_HPP

#include <map>
#include <string>

#include "Transactor.hpp"
#include "Notary.hpp"
#include "MainFile.hpp"
#include "UserCommandProcessor.hpp"
#include <opentxs/core/util/Common.hpp>
#include <opentxs/core/cron/OTCron.hpp>
#include <opentxs/core/Nym.hpp>
#include <opentxs/core/OTTransaction.hpp>
#include <memory>
#include <cstddef>
#include <czmq.h>

namespace opentxs
{

class Identifier;
class Message;
class OTPayment;
class ServerContract;

class OTServer
{
    friend class Transactor;
    friend class MessageProcessor;
    friend class UserCommandProcessor;
    friend class MainFile;
    friend class PayDividendVisitor;
    friend class Notary;

private:
    const std::string DEFAULT_EXTERNAL_IP = "127.0.0.1";
    const std::string DEFAULT_BIND_IP = "127.0.0.1";
    const std::string DEFAULT_NAME = "localhost";
    const uint32_t DEFAULT_COMMAND_PORT = 7085;
    const uint32_t DEFAULT_NOTIFY_PORT = 7086;
    const uint32_t MIN_TCP_PORT = 1024;
    const uint32_t MAX_TCP_PORT = 63356;

public:
    EXPORT OTServer();
    EXPORT ~OTServer();

    EXPORT void Init(
        std::map<std::string, std::string>& args,
        bool readOnly = false);

    bool IsFlaggedForShutdown() const;

    bool GetConnectInfo(std::string& hostname, uint32_t& port) const;
    zcert_t* GetTransportKey() const;

    const Nym& GetServerNym() const;

    EXPORT void ActivateCron();
    void ProcessCron();
    int64_t computeTimeout()
    {
        return m_Cron.computeTimeout();
    }

private:
    void CreateMainFile(
        bool& mainFileExists,
        std::map<std::string, std::string>& args);
    bool SendInstrumentToNym(const Identifier& notaryID,
                             const Identifier& senderNymID,
                             const Identifier& recipientNymID,
                             Message* msg = nullptr,
                             const OTPayment* payment = nullptr,
                             const char* command = nullptr);

    // Note: SendInstrumentToNym and SendMessageToNym CALL THIS.
    // They are higher-level, this is lower-level.
    bool DropMessageToNymbox(const Identifier& notaryID,
                             const Identifier& senderNymID,
                             const Identifier& recipientNymID,
                             OTTransaction::transactionType transactionType,
                             Message* msg = nullptr,
                             const String* messageString = nullptr,
                             const char* command = nullptr);

private:
    MainFile mainFile_;
    Notary notary_;
    Transactor transactor_;
    UserCommandProcessor userCommandProcessor_;

    String m_strWalletFilename;
    // Used at least for whether or not to write to the PID.
    bool m_bReadOnly;
    // If the server wants to be shut down, it can set
    // this flag so the caller knows to do so.
    bool m_bShutdownFlag;

    // A hash of the server contract
    String m_strNotaryID;
    // A hash of the public key that signed the server contract
    String m_strServerNymID;
    // This is the server's own contract, containing its public key and
    // connect info.

    Nym m_nymServer;

    OTCron m_Cron; // This is where re-occurring and expiring tasks go.
};

} // namespace opentxs

#endif // OPENTXS_SERVER_OTSERVER_HPP
