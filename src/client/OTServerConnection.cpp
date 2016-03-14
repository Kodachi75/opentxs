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

#include <opentxs/core/stdafx.hpp>

#include <opentxs/client/OTServerConnection.hpp>
#include <opentxs/client/OTClient.hpp>
#include <opentxs/core/crypto/OTEnvelope.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/Message.hpp>
#include <opentxs/core/Nym.hpp>
#include <opentxs/core/contract/ServerContract.hpp>

#include <czmq.h>

#define CLIENT_SOCKET_LINGER 1000
#define CLIENT_SEND_TIMEOUT 1000
#define CLIENT_RECV_TIMEOUT 10000

namespace opentxs
{

// static ---------------------------------------------------
int  OTServerConnection::s_linger          = CLIENT_SOCKET_LINGER;
int  OTServerConnection::s_send_timeout    = CLIENT_SEND_TIMEOUT;
int  OTServerConnection::s_recv_timeout    = CLIENT_RECV_TIMEOUT;
bool OTServerConnection::s_bNetworkFailure = false;

int OTServerConnection::getLinger()
{
    return s_linger;
}

int OTServerConnection::getSendTimeout()
{
    return s_send_timeout;
}

int OTServerConnection::getRecvTimeout()
{
    return s_recv_timeout;
}

void OTServerConnection::setLinger(int nIn)
{
    s_linger = nIn;
}

void OTServerConnection::setSendTimeout(int nIn)
{
    s_send_timeout = nIn;
}

void OTServerConnection::setRecvTimeout(int nIn)
{
    s_recv_timeout = nIn;
}

// This returns m_bNetworkFailure
bool OTServerConnection::networkFailure()
{
    return s_bNetworkFailure;
}

// end static -----------------------------------------------


// When a certain Nym opens a certain account on a certain server,
// that account is put onto a list of accounts inside the wallet.
// Therefore, a certain Nym's connection to a certain server will
// occasionally require access to those accounts. Therefore the
// server connection object needs to have a pointer to the wallet.
// There might be MORE THAN ONE connection per wallet, or only one,
// but either way the connections need a pointer to the wallet
// they are associated with, so they can access those accounts.
OTServerConnection::OTServerConnection(OTClient* theClient,
                                       const std::string& endpoint,
                                       const unsigned char* transportKey)
    : socket_zmq(zsock_new_req(NULL))
    , m_pNym(nullptr)
    , m_pServerContract(nullptr)
    , m_pClient(theClient)
    , m_endpoint(endpoint)
{
    if (!zsys_has_curve()) {
        Log::vError("Error: libzmq has no libsodium support");
        OT_FAIL;
    }

    zsock_set_linger(socket_zmq, OTServerConnection::getLinger());
    zsock_set_sndtimeo(socket_zmq, OTServerConnection::getSendTimeout());
    zsock_set_rcvtimeo(socket_zmq, OTServerConnection::getRecvTimeout());

    // Set new client public and secret key.
    zcert_apply(zcert_new(), socket_zmq);
    // Set server public key.
    zsock_set_curve_serverkey_bin(socket_zmq, transportKey);

    s_bNetworkFailure = false;

    if (zsock_connect(socket_zmq, "%s", m_endpoint.c_str())) {
        s_bNetworkFailure = true;
        Log::vError("Failed to connect to %s\n", m_endpoint.c_str());
        OT_FAIL;
    }
}

OTServerConnection::~OTServerConnection()
{
    zsock_destroy(&socket_zmq);
}


bool OTServerConnection::resetSocket()
{
    if (!m_pServerContract) {
        otErr << __FUNCTION__ << ": Failed trying to reset socket due to missing server contract.\n";
        return false;
    }

    zsock_destroy(&socket_zmq);
    socket_zmq = zsock_new_req(NULL);

    if (!socket_zmq) {
        otErr << __FUNCTION__ << ": Failed trying to reset socket.\n";
        return false;
    }

    zsock_set_linger(socket_zmq, OTServerConnection::getLinger());
    zsock_set_sndtimeo(socket_zmq, OTServerConnection::getSendTimeout());
    zsock_set_rcvtimeo(socket_zmq, OTServerConnection::getRecvTimeout());

    // Set new client public and secret key.
    zcert_apply(zcert_new(), socket_zmq);
    // Set server public key.
    zsock_set_curve_serverkey_bin(
        socket_zmq,
        m_pServerContract->PublicTransportKey());

    if (zsock_connect(socket_zmq, "%s", m_endpoint.c_str())) {
        s_bNetworkFailure = true;
        Log::vError("Failed to connect to %s\n", m_endpoint.c_str());
        OT_FAIL;
    }

    return true;
}

// When the server sends a reply back with our new request number, we
// need to update our records accordingly.
//
// This function is meant to be called when that happens, so that we
// can do just that.
//
void OTServerConnection::OnServerResponseToGetRequestNumber(
    int64_t lNewRequestNumber) const
{
    if (m_pNym && m_pServerContract) {
        otOut << "Received new request number from the server: "
              << lNewRequestNumber << ". Updating Nym records...\n";

        m_pNym->OnUpdateRequestNum(
            *m_pNym,  m_pServerContract->ID(), lNewRequestNumber);
    }
    else {
        otErr << "Expected m_pNym or m_pServerContract to be not null in "
                 "OTServerConnection::OnServerResponseToGetRequestNumber.\n";
    }
}

bool OTServerConnection::GetNotaryID(Identifier& theID) const
{
    if (m_pServerContract) {
        theID = m_pServerContract->ID();
        return true;
    }
    return false;
}

void OTServerConnection::send(const ServerContract* pServerContract, Nym* pNym,
                              const Message& theMessage)
{
    OT_ASSERT(nullptr != pServerContract);
    OT_ASSERT(nullptr != pNym)
    /* What are these lines intended to do?
    const Nym* pServerNym = pServerContract->GetContractPublicNym();
    OT_ASSERT(nullptr != pServerNym);*/

    String strContents;
    theMessage.SaveContractRaw(strContents);

    otOut << "\n=====>BEGIN Sending " << theMessage.m_strCommand
          << " message via ZMQ... Request number: "
          << theMessage.m_strRequestNum << "\n";

    m_pServerContract = pServerContract;
    m_pNym = pNym;
    send(strContents);

    otWarn << "<=====END Finished sending " << theMessage.m_strCommand
           << " message (and hopefully receiving "
              "a reply.)\nRequest number: " << theMessage.m_strRequestNum
           << "\n\n";
}

bool OTServerConnection::send(const String& theString)
{
    OTASCIIArmor ascEnvelope(theString);

    if (!ascEnvelope.Exists()) {
        return false;
    }

    s_bNetworkFailure = false;

    int rc = zstr_send(socket_zmq, ascEnvelope.Get());

    if (rc != 0) {
        s_bNetworkFailure = true;
        otErr << __FUNCTION__
              << ": Failed while trying to send message to server.\n";

        resetSocket();

        return false;
    }
//  else
//      otErr << __FUNCTION__ << ": DEBUGGING!!!! SUCCESSFULLY SENT. \n";


    std::string rawServerReply;
    bool bSuccessReceiving = receive(rawServerReply);

    if (!bSuccessReceiving) {
        s_bNetworkFailure = true;
        otErr << __FUNCTION__ << ": Failed trying to receive expected reply "
                                 "from server.\n";

        resetSocket();

        return false;
    }
//    else
//        otErr << __FUNCTION__ << ": DEBUGGING!!!! SUCCESSFULLY RECEIVED. \n";


    OTASCIIArmor ascServerReply;
    ascServerReply.Set(rawServerReply.c_str());

    String strServerReply;
    bool bRetrievedReply = ascServerReply.GetString(strServerReply);

    // todo: use a unique_ptr  soon as feasible.
    std::shared_ptr<Message> pServerReply(new Message());
    OT_ASSERT(nullptr != pServerReply);

    if (bRetrievedReply && strServerReply.Exists() &&
        pServerReply->LoadContractFromString(strServerReply)) {
        // Now the fully-loaded message object (from the server,
        // this time) can be processed by the OT library...
        // Client takes ownership and will
        m_pClient->processServerReply(pServerReply);
    }
    else {
        otErr << __FUNCTION__ << ": Error loading server reply from string:\n\n"
              << rawServerReply << "\n\n";
        return false;
    }

    return true;
}

bool OTServerConnection::receive(std::string& serverReply)
{
    char* msg = zstr_recv(socket_zmq);
    if (msg == nullptr) return false;
    serverReply.assign(msg);
    zstr_free(&msg);
    return true;
}

} // namespace opentxs
