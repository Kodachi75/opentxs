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

#ifndef OPENTXS_CLIENT_OTCLIENT_HPP
#define OPENTXS_CLIENT_OTCLIENT_HPP

#include <opentxs/client/OTMessageBuffer.hpp>
#include <opentxs/client/OTMessageOutbuffer.hpp>
#include <opentxs/client/OTServerConnection.hpp>
#include <string>
#include <memory>

namespace opentxs
{

class Account;
class UnitDefinition;
class Ledger;
class ServerContract;
class OTWallet;

class OTClient
{
public:
    enum OT_CLIENT_CMD_TYPE {
        pingNotary, // Your public key is sent along with this message so the
                    // server can reply to
        // you even without your being a registered user. Other than these top
        // two commands,
        // all other commands can only be executed by registered users.
        //
        // The server ID is a hash of the server contract. The signature on the
        // contract
        // can be verified by a public key that appears in a standard section of
        // any server
        // contract. The URL/port information is also derived from the contract.
        //
        // Simply by importing the server contract into your wallet, you are
        // able to connect
        // to it and encrypt all of your communications to it.
        //
        // Thus, the check server ID command really just confirms what you
        // should already know...
        // Your wallet still wants to see that the server agrees with the server
        // ID, and that
        // the server is able to read messages that were encrypted to the public
        // key in the
        // contract, and that the server is able to sign all of its future
        // correspondence with
        // the same public key.
        //
        // It is the server operator's responsibility to secure the domain name
        // and web host
        // that users will connect to when they import the contract, as well as
        // the private
        // key that matches the public key from the contract.
        registerNym,      // register user account on a specific server, with
                          // public key. Nym ID will be hash of said public
                          // key.
        unregisterNym,    // Delete user account from a specific server.
        getRequestNumber, // Get the next request number from the server (for
                          // this
                          // user). Most requests must be
        // accompanied by a request number, which increments for each Nym with
        // each request.
        getTransactionNumbers, // Every transaction requires a transaction
                               // number.
                               // If your wallet doesn't have one,
        // then here it can request the server to send one over. (Or several.)
        processNymbox, // Used by AcceptEntireNymbox() as it's setting
                       // everything up.
        writeCheque, // Write a cheque. (Actually sends no message to the server
                     // -- returns false.)
        notarizePurse, // Same as the above, but sends an entire purse of tokens
                       // at once instead of sending individual tokens.
        notarizeCheque, // Deposit like the above, but deposits a cheque instead
                        // of cash tokens.
        paymentPlan, // Send a payment plan to the server (request to activate
                     // one onto yourself, basically.)
        // The test client will ask you to input the plan, which you must
        // already have (like a cheque).
        // The Payee must create it and sign it, then he sends it to the Payer,
        // who uses this command
        // to sign it and submit it to the server.
        badID
    };

public:
    explicit OTClient(OTWallet* theWallet);

    bool connect(const std::string& endpoint,
                 const unsigned char* transportKey);

    inline OTMessageBuffer& GetMessageBuffer()
    {
        return m_MessageBuffer;
    }

    inline OTMessageOutbuffer& GetMessageOutbuffer()
    {
        return m_MessageOutbuffer;
    }

    void ProcessMessageOut(const ServerContract* pServerContract, Nym* pNym,
                           const Message& theMessage);
    bool ProcessInBuffer(const Message& theServerReply) const;

    EXPORT int32_t ProcessUserCommand(OT_CLIENT_CMD_TYPE requestedCommand,
                                      Message& theMessage, Nym& theNym,
                                      const ServerContract& theServer,
                                      const Account* pAccount = nullptr,
                                      int64_t lTransactionAmount = 0,
                                      const UnitDefinition* pMyUnitDefinition = nullptr,
                                      const Identifier* pHisNymID = nullptr,
                                      const Identifier* pHisAcctID = nullptr);

    bool processServerReply(std::shared_ptr<Message> theReply,
                            Ledger* pNymbox = nullptr);

    bool AcceptEntireNymbox(Ledger& theNymbox, const Identifier& theNotaryID,
                            const ServerContract& theServerContract,
                            Nym& theNym, Message& theMessage);

private:
    void ProcessIncomingTransactions(OTServerConnection& theConnection,
                                     const Message& theReply) const;
    void ProcessWithdrawalResponse(OTTransaction& theTransaction,
                                   const OTServerConnection& theConnection,
                                   const Message& theReply) const;
    void ProcessDepositResponse(OTTransaction& theTransaction,
                                const OTServerConnection& theConnection,
                                const Message& theReply) const;
    void ProcessPayDividendResponse(OTTransaction& theTransaction,
                                    const OTServerConnection& theConnection,
                                    const Message& theReply) const;

    void load_str_trans_add_to_ledger(const Identifier& the_nym_id,
                                      const String& str_trans,
                                      String str_box_type,
                                      const int64_t& lTransNum, Nym& the_nym,
                                      Ledger& ledger) const;

    struct ProcessServerReplyArgs;
    void setRecentHash(const Message& theReply, const String& strNotaryID,
                       Nym* pNym, bool setNymboxHash);
    bool processServerReplyTriggerClause(const Message& theReply,
                                         ProcessServerReplyArgs& args);
    bool processServerReplyGetRequestNumber(const Message& theReply,
                                            ProcessServerReplyArgs& args);
    bool processServerReplyCheckNym(const Message& theReply,
                                    ProcessServerReplyArgs& args);
    bool processServerReplyNotarizeTransaction(const Message& theReply,
                                               ProcessServerReplyArgs& args);
    bool processServerReplyGetTransactionNumbers(const Message& theReply,
                                                 ProcessServerReplyArgs& args);
    bool processServerReplyGetNymBox(const Message& theReply, Ledger* pNymbox,
                                     ProcessServerReplyArgs& args);
    bool processServerReplyGetBoxReceipt(const Message& theReply,
                                         Ledger* pNymbox,
                                         ProcessServerReplyArgs& args);
    bool processServerReplyProcessInbox(const Message& theReply,
                                        Ledger* pNymbox,
                                        ProcessServerReplyArgs& args);
    bool processServerReplyGetAccountData(const Message& theReply,
                                          Ledger* pNymbox,
                                          ProcessServerReplyArgs& args);
    bool processServerReplyGetInstrumentDefinition(
        const Message& theReply, ProcessServerReplyArgs& args);
    bool processServerReplyGetMint(const Message& theReply);
    bool processServerReplyGetMarketList(const Message& theReply);
    bool processServerReplyGetMarketOffers(const Message& theReply);
    bool processServerReplyGetMarketRecentTrades(const Message& theReply);
    bool processServerReplyGetNymMarketOffers(const Message& theReply);
    bool processServerReplyUnregisterNym(const Message& theReply,
                                         ProcessServerReplyArgs& args);
    bool processServerReplyUnregisterAccount(const Message& theReply,
                                             ProcessServerReplyArgs& args);
    bool processServerReplyRegisterInstrumentDefinition(
        const Message& theReply, ProcessServerReplyArgs& args);
    bool processServerReplyRegisterAccount(const Message& theReply,
                                           ProcessServerReplyArgs& args);

private:
    std::unique_ptr<OTServerConnection> m_pConnection;
    OTWallet* m_pWallet;
    OTMessageBuffer m_MessageBuffer;
    OTMessageOutbuffer m_MessageOutbuffer;
};

} // namespace opentxs

#endif // OPENTXS_CLIENT_OTCLIENT_HPP
