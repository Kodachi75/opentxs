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

#include <chrono>

#include <opentxs/server/ServerSettings.hpp>
#include <opentxs/server/ServerLoader.hpp>
#include <opentxs/server/MessageProcessor.hpp>
#include <opentxs/server/OTServer.hpp>
#include <opentxs/server/ClientConnection.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/Message.hpp>
#include <opentxs/core/String.hpp>
#include <opentxs/core/util/OTDataFolder.hpp>
#include <opentxs/core/crypto/OTEnvelope.hpp>
#include <opentxs/core/util/Timer.hpp>

#include <czmq.h>

namespace opentxs
{

MessageProcessor::MessageProcessor(ServerLoader& loader)
    : server_(loader.getServer())
    , zmqSocket_(zsock_new_rep(NULL))
    , zmqAuth_(zactor_new(zauth, NULL))
    , zmqPoller_(zpoller_new(zmqSocket_, NULL))
{
    init(loader.getPort(), loader.getTransportKey());
}

MessageProcessor::~MessageProcessor()
{
    zpoller_remove(zmqPoller_, zmqSocket_);
    zpoller_destroy(&zmqPoller_);
    zactor_destroy(&zmqAuth_);
    zsock_destroy(&zmqSocket_);
}

void MessageProcessor::init(int port, zcert_t* transportKey)
{
    if (port == 0) {
        OT_FAIL;
    }
    if (!zsys_has_curve()) {
        Log::vError("Error: libzmq has no libsodium support");
        OT_FAIL;
    }
    zstr_sendx(zmqAuth_, "CURVE", CURVE_ALLOW_ANY, NULL);
    zsock_wait(zmqAuth_);
    zsock_set_zap_domain(zmqSocket_, "global");
    zsock_set_curve_server(zmqSocket_, 1);
    zcert_apply(transportKey, zmqSocket_);
    zcert_destroy(&transportKey);
    zsock_bind(zmqSocket_, "tcp://*:%d", port);
}

void MessageProcessor::run()
{
    for (;;) {
        // timeout is the time left until the next cron should execute.
        int64_t timeout = server_->computeTimeout();
        if (timeout <= 0) {
            server_->ProcessCron();
            continue;
        }

        // wait for incoming message or up to timeout,
        // i.e. stop polling in time for the next cron execution.
        if (zpoller_wait(zmqPoller_, timeout)) {
            processSocket();
            continue;
        }
        if (zpoller_terminated(zmqPoller_)) {
            otErr << __FUNCTION__
                  << ": zpoller_terminated - process interrupted or"
                  << " parent context destroyed\n";
            break;
        }

        if (!zpoller_expired(zmqPoller_)) {
            otErr << __FUNCTION__ << ": zpoller_wait error\n";
        }

        Log::Sleep(std::chrono::milliseconds(100));
    }
}

void MessageProcessor::processSocket()
{
    char* msg = zstr_recv(zmqSocket_);
    if (msg == nullptr) {
        Log::Error("zeromq recv() failed\n");
        return;
    }
    std::string requestString(msg);
    zstr_free(&msg);

    std::string responseString;

    bool error = processMessage(requestString, responseString);

    if (error) {
        responseString = "";
    }

    int rc = zstr_send(zmqSocket_, responseString.c_str());

    if (rc != 0) {
        Log::vError("MessageProcessor: failed to send response\n"
                    "request:\n%s\n\n"
                    "response:\n%s\n\n",
                    requestString.c_str(), responseString.c_str());
    }
}

bool MessageProcessor::processMessage(const std::string& messageString,
                                      std::string& reply)
{
    if (messageString.size() < 1) return false;

    // First we grab the client's message
    OTASCIIArmor ascMessage;
    ascMessage.MemSet(messageString.data(), messageString.size());

    String messageContents;
    ascMessage.GetString(messageContents);
    // All decrypted--now let's load the results into an OTMessage.
    // No need to call message.ParseRawFile() after, since
    // LoadContractFromString handles it.
    Message message;
    if (!messageContents.Exists() ||
        !message.LoadContractFromString(messageContents)) {
        Log::vError("Error loading message from message "
                    "contents:\n\n%s\n\n",
                    messageContents.Get());
        return true;
    }

    Message replyMessage;
    replyMessage.m_strCommand.Format("%sResponse", message.m_strCommand.Get());
    // NymID
    replyMessage.m_strNymID = message.m_strNymID;
    // NotaryID, a hash of the server contract
    replyMessage.m_strNotaryID = message.m_strNotaryID;
    // The default reply. In fact this is probably superfluous
    replyMessage.m_bSuccess = false;

    ClientConnection client;
    Nym nym(message.m_strNymID);

    bool processedUserCmd = server_->userCommandProcessor_.ProcessUserCommand(
        message, replyMessage, &client, &nym);

    // By optionally passing in &client, the client Nym's public
    // key will be set on it whenever verification is complete. (So
    // for the reply, I'll  have the key and thus I'll be able to
    // encrypt reply to the recipient.)
    if (!processedUserCmd) {
        String s1(message);

        Log::vOutput(0, "Unable to process user command: %s\n ********** "
                        "REQUEST:\n\n%s\n\n",
                     message.m_strCommand.Get(), s1.Get());

        // NOTE: normally you would even HAVE a true or false if
        // we're in this block. ProcessUserCommand()
        // is what tries to process a command and then sets false
        // if/when it fails. Until that point, you
        // wouldn't get any server reply.  I'm now changing this
        // slightly, so you still get a reply (defaulted
        // to success==false.) That way if a client needs to re-sync
        // his request number, he will get the false
        // and therefore know to resync the # as his next move, vs
        // being stuck with no server reply (and thus
        // stuck with a bad socket.)
        // We sign the reply here, but not in the else block, since
        // it's already signed in cases where
        // ProcessUserCommand() is a success, by the time that call
        // returns.

        // Since the process call definitely failed, I'm
        replyMessage.m_bSuccess = false;
        // making sure this here is definitely set to
        // false (even though it probably was already.)
        replyMessage.SignContract(server_->GetServerNym());
        replyMessage.SaveContract();

        String s2(replyMessage);

        Log::vOutput(0, " ********** RESPONSE:\n\n%s\n\n", s2.Get());
    }
    else {
        // At this point the reply is ready to go, and client
        // has the public key of the recipient...
        Log::vOutput(1, "Successfully processed user command: %s.\n",
                     message.m_strCommand.Get());
    }

    String replyString(replyMessage);

    if (!replyString.Exists()) {
        Log::vOutput(0, "Failed trying to grab the reply "
                        "in OTString form. "
                        "(No reply message will be sent.)\n");
        return true;
    }

    OTASCIIArmor ascReply(replyString);

    if (!ascReply.Exists()) {
        Log::vOutput(0, "Unable to WriteArmoredString from "
                        "OTASCIIArmor object into OTString object. (No reply "
                        "message will be sent.)\n");
        return true;
    }

    reply.assign(ascReply.Get(), ascReply.GetLength());

    return false;
}

} // namespace opentxs
