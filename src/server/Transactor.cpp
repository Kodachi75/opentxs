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

#include <opentxs/server/Transactor.hpp>
#include <opentxs/server/OTServer.hpp>

#include <opentxs/cash/Mint.hpp>
#include <opentxs/core/util/OTFolders.hpp>
#include <opentxs/core/Account.hpp>
#include <opentxs/core/Identifier.hpp>
#include <opentxs/core/Nym.hpp>
#include <opentxs/core/String.hpp>
#include <opentxs/core/Log.hpp>

namespace opentxs
{

Transactor::Transactor(OTServer* server)
    : transactionNumber_(0)
    , server_(server)
{
}

Transactor::~Transactor()
{
    while (!mintsMap_.empty()) {
        auto it = mintsMap_.begin();
        Mint* pMint = it->second;
        OT_ASSERT(nullptr != pMint);
        mintsMap_.erase(it);
        delete pMint;
        pMint = nullptr;
    }
}

/// Just as every request must be accompanied by a request number, so
/// every transaction request must be accompanied by a transaction number.
/// The request numbers can simply be incremented on both sides (per user.)
/// But the transaction numbers must be issued by the server and they do
/// not repeat from user to user. They are unique to transaction.
///
/// Users must ask the server to send them transaction numbers so that they
/// can be used in transaction requests.
bool Transactor::issueNextTransactionNumber(int64_t& lTransactionNumber)
{
    // transactionNumber_ stores the last VALID AND ISSUED transaction number.
    // So first, we increment that, since we don't want to issue the same number
    // twice.
    transactionNumber_++;

    // Next, we save it to file.
    if (!server_->mainFile_.SaveMainFile()) {
        Log::Error("Error saving main server file.\n");
        transactionNumber_--;
        return false;
    }

    // SUCCESS?
    // Now the server main file has saved the latest transaction number,
    // NOW we set it onto the parameter and return true.
    lTransactionNumber = transactionNumber_;
    return true;
}

bool Transactor::issueNextTransactionNumberToNym(Nym& theNym,
                                                 int64_t& lTransactionNumber)
{
    Identifier NYM_ID(theNym), NOTARY_NYM_ID(server_->m_nymServer);

    // If theNym has the same ID as server_->m_nymServer, then we'll use
    // server_->m_nymServer
    // instead of theNym.  (Since it's the same nym anyway, we'll stick to the
    // one we already loaded so any changes don't get overwritten later.)
    Nym* pNym = nullptr;

    if (NYM_ID == NOTARY_NYM_ID)
        pNym = &server_->m_nymServer;
    else
        pNym = &theNym;

    if (!issueNextTransactionNumber(lTransactionNumber)) {
        return false;
    }

    // Each Nym stores the transaction numbers that have been issued to it.
    // (On client AND server side.)
    //
    // So whenever the server issues a new number, it's to a specific Nym, then
    // it is recorded in his Nym file before being sent to the client (where it
    // is also recorded in his Nym file.)  That way the server always knows
    // which
    // numbers are valid for each Nym.
    if (!pNym->AddTransactionNum(server_->m_nymServer, server_->m_strNotaryID,
                                 transactionNumber_, true)) {
        Log::Error("Error adding transaction number to Nym file.\n");
        transactionNumber_--;
        server_->mainFile_.SaveMainFile(); // Save it back how it was, since
                                           // we're not
                                           // issuing this
                                           // number after all.
        return false;
    }

    // SUCCESS?
    // Now the server main file has saved the latest transaction number,
    // NOW we set it onto the parameter and return true.
    lTransactionNumber = transactionNumber_;
    return true;
}

/// Transaction numbers are now stored in the nym file (on client and server
/// side) for whichever nym
/// they were issued to. This function verifies whether or not the transaction
/// number is present and valid
/// for any specific nym (i.e. for the nym passed in.)
bool Transactor::verifyTransactionNumber(
    Nym& theNym, const int64_t& lTransactionNumber) // passed by
                                                    // reference for
                                                    // speed, but not a
                                                    // return value.
{
    Identifier NYM_ID(theNym), NOTARY_NYM_ID(server_->m_nymServer);

    // If theNym has the same ID as server_->m_nymServer, then we'll use
    // server_->m_nymServer
    // instead of theNym.  (Since it's the same nym anyway, we'll stick to the
    // one we already loaded so any changes don't get overwritten later.)
    Nym* pNym = nullptr;

    if (NYM_ID == NOTARY_NYM_ID)
        pNym = &server_->m_nymServer;
    else
        pNym = &theNym;
    if (pNym->VerifyTransactionNum(server_->m_strNotaryID, lTransactionNumber))
        return true;
    else {
        const String strNymID(NYM_ID);
        const String strIssued(
            pNym->VerifyIssuedNum(server_->m_strNotaryID, lTransactionNumber)
                ? "(However, that number IS issued to that Nym... He must have "
                  "already used it.)\n"
                : "(In fact, that number isn't even issued to that Nym, though "
                  "perhaps it was at some time in the past?)\n");

        Log::vError("%s: %" PRId64 " not available for Nym %s to use. \n%s",
                    __FUNCTION__,
                    //                    " Oh, and FYI, tangentially, the
                    // current Trns# counter is: %ld\n",
                    lTransactionNumber, strNymID.Get(), strIssued.Get());
        //                    transactionNumber_);
    }

    return false;
}

/// Remove a transaction number from the Nym record once it's officially
/// used/spent.
bool Transactor::removeTransactionNumber(Nym& theNym,
                                         const int64_t& lTransactionNumber,
                                         bool bSave)
{
    Identifier NYM_ID(theNym), NOTARY_NYM_ID(server_->m_nymServer);

    // If theNym has the same ID as server_->m_nymServer, then we'll use
    // server_->m_nymServer
    // instead of theNym.  (Since it's the same nym anyway, we'll stick to the
    // one we already loaded so any changes don't get overwritten later.)
    Nym* pNym = nullptr;

    if (NYM_ID == NOTARY_NYM_ID)
        pNym = &server_->m_nymServer;
    else
        pNym = &theNym;

    bool bRemoved = false;

    if (bSave)
        bRemoved = pNym->RemoveTransactionNum(
            server_->m_nymServer, server_->m_strNotaryID,
            lTransactionNumber); // the version that passes in a signer nym --
                                 // saves to local storage.
    else
        bRemoved = pNym->RemoveTransactionNum(
            server_->m_strNotaryID,
            lTransactionNumber); // the version that doesn't save.

    return bRemoved;
}

/// Remove an issued number from the Nym record once that nym accepts the
/// receipt from his inbox.
bool Transactor::removeIssuedNumber(Nym& theNym,
                                    const int64_t& lTransactionNumber,
                                    bool bSave)
{
    Identifier NYM_ID(theNym), NOTARY_NYM_ID(server_->m_nymServer);

    // If theNym has the same ID as server_->m_nymServer, then we'll use
    // server_->m_nymServer
    // instead of theNym.  (Since it's the same nym anyway, we'll stick to the
    // one we already loaded so any changes don't get overwritten later.)
    Nym* pNym = nullptr;

    if (NYM_ID == NOTARY_NYM_ID)
        pNym = &server_->m_nymServer;
    else
        pNym = &theNym;

    bool bRemoved =
        pNym->RemoveIssuedNum(server_->m_nymServer, server_->m_strNotaryID,
                              lTransactionNumber, bSave);

    return bRemoved;
}

// Server stores a map of BASKET_ID to BASKET_ACCOUNT_ID.
bool Transactor::addBasketAccountID(const Identifier& BASKET_ID,
                                    const Identifier& BASKET_ACCOUNT_ID,
                                    const Identifier& BASKET_CONTRACT_ID)
{
    Identifier theBasketAcctID;

    if (lookupBasketAccountID(BASKET_ID, theBasketAcctID)) {
        Log::Output(0, "User attempted to add Basket that already exists.\n");
        return false;
    }

    String strBasketID(BASKET_ID), strBasketAcctID(BASKET_ACCOUNT_ID),
        strBasketContractID(BASKET_CONTRACT_ID);

    idToBasketMap_[strBasketID.Get()] = strBasketAcctID.Get();
    contractIdToBasketAccountId_[strBasketContractID.Get()] =
        strBasketAcctID.Get();

    return true;
}

/// Use this to find the basket account ID for this server (which is unique to
/// this server)
/// using the contract ID to look it up. (The basket contract ID is unique to
/// this server.)
bool Transactor::lookupBasketAccountIDByContractID(
    const Identifier& BASKET_CONTRACT_ID, Identifier& BASKET_ACCOUNT_ID)
{
    // Server stores a map of BASKET_ID to BASKET_ACCOUNT_ID. Let's iterate
    // through that map...
    for (auto& it : contractIdToBasketAccountId_) {
        String strBasketContractID = it.first.c_str();
        String strBasketAcctID = it.second.c_str();

        Identifier id_BASKET_CONTRACT(strBasketContractID),
            id_BASKET_ACCT(strBasketAcctID);

        if (BASKET_CONTRACT_ID == id_BASKET_CONTRACT) // if the basket contract
                                                      // ID passed in matches
                                                      // this one...
        {
            BASKET_ACCOUNT_ID = id_BASKET_ACCT;
            return true;
        }
    }
    return false;
}

/// Use this to find the basket account ID for this server (which is unique to
/// this server)
/// using the contract ID to look it up. (The basket contract ID is unique to
/// this server.)
bool Transactor::lookupBasketContractIDByAccountID(
    const Identifier& BASKET_ACCOUNT_ID, Identifier& BASKET_CONTRACT_ID)
{
    // Server stores a map of BASKET_ID to BASKET_ACCOUNT_ID. Let's iterate
    // through that map...
    for (auto& it : contractIdToBasketAccountId_) {
        String strBasketContractID = it.first.c_str();
        String strBasketAcctID = it.second.c_str();

        Identifier id_BASKET_CONTRACT(strBasketContractID),
            id_BASKET_ACCT(strBasketAcctID);

        if (BASKET_ACCOUNT_ID == id_BASKET_ACCT) // if the basket contract ID
                                                 // passed in matches this
                                                 // one...
        {
            BASKET_CONTRACT_ID = id_BASKET_CONTRACT;
            return true;
        }
    }
    return false;
}

/// Use this to find the basket account for this server (which is unique to this
/// server)
/// using the basket ID to look it up (the Basket ID is the same for all
/// servers)
bool Transactor::lookupBasketAccountID(const Identifier& BASKET_ID,
                                       Identifier& BASKET_ACCOUNT_ID)
{
    // Server stores a map of BASKET_ID to BASKET_ACCOUNT_ID. Let's iterate
    // through that map...
    for (auto& it : idToBasketMap_) {
        String strBasketID = it.first.c_str();
        String strBasketAcctID = it.second.c_str();

        Identifier id_BASKET(strBasketID), id_BASKET_ACCT(strBasketAcctID);

        if (BASKET_ID ==
            id_BASKET) // if the basket ID passed in matches this one...
        {
            BASKET_ACCOUNT_ID = id_BASKET_ACCT;
            return true;
        }
    }
    return false;
}

/// Looked up the voucher account (where cashier's cheques are issued for any
/// given instrument definition) return a pointer to the account.  Since it's
/// SUPPOSED to
/// exist, and since it's being requested, also will GENERATE it if it cannot
/// be found, add it to the list, and return the pointer. Should always succeed.
std::shared_ptr<Account> Transactor::getVoucherAccount(
    const Identifier& INSTRUMENT_DEFINITION_ID)
{
    std::shared_ptr<Account> pAccount;
    const Identifier NOTARY_NYM_ID(server_->m_nymServer),
        NOTARY_ID(server_->m_strNotaryID);
    bool bWasAcctCreated = false;
    pAccount = voucherAccounts_.GetOrRegisterAccount(
        server_->m_nymServer, NOTARY_NYM_ID, INSTRUMENT_DEFINITION_ID,
        NOTARY_ID, bWasAcctCreated);
    if (bWasAcctCreated) {
        String strAcctID;
        pAccount->GetIdentifier(strAcctID);
        const String strInstrumentDefinitionID(INSTRUMENT_DEFINITION_ID);

        Log::vOutput(0, "OTServer::GetVoucherAccount: Successfully created "
                        "voucher account ID: %s Instrument Definition ID: %s\n",
                     strAcctID.Get(), strInstrumentDefinitionID.Get());

        if (!server_->mainFile_.SaveMainFile()) {
            Log::Error("OTServer::GetVoucherAccount: Error saving main "
                       "server file containing new account ID!!\n");
        }
    }

    return pAccount;
}

/// Lookup the current mint for any given instrument definition ID and series.
Mint* Transactor::getMint(const Identifier& INSTRUMENT_DEFINITION_ID,
                          int32_t nSeries) // Each asset contract has its own
                                           // Mint.
{
    Mint* pMint = nullptr;

    for (auto& it : mintsMap_) {
        pMint = it.second;
        OT_ASSERT_MSG(nullptr != pMint,
                      "nullptr mint pointer in Transactor::getMint\n");

        Identifier theID;
        pMint->GetIdentifier(theID);

        if ((INSTRUMENT_DEFINITION_ID ==
             theID) && // if the ID on the Mint matches the ID passed in
            (nSeries == pMint->GetSeries())) // and the series also matches...
            return pMint; // return the pointer right here, we're done.
    }
    // The mint isn't in memory for the series requested.
    const String INSTRUMENT_DEFINITION_ID_STR(INSTRUMENT_DEFINITION_ID);

    String strMintFilename;
    strMintFilename.Format("%s%s%s%s%d", server_->m_strNotaryID.Get(),
                           Log::PathSeparator(),
                           INSTRUMENT_DEFINITION_ID_STR.Get(), ".", nSeries);

    const char* szFoldername = OTFolders::Mint().Get();
    const char* szFilename = strMintFilename.Get();
    pMint = Mint::MintFactory(server_->m_strNotaryID, server_->m_strServerNymID,
                              INSTRUMENT_DEFINITION_ID_STR);

    // You cannot hash the Mint to get its ID. (The ID is a hash of the asset
    // contract.)
    // Instead, you must READ the ID from the Mint file, and then compare it to
    // the one expected
    // to see if they match (similar to how Account IDs are verified.)

    OT_ASSERT_MSG(nullptr != pMint,
                  "Error allocating memory for Mint in Transactor::getMint");
    String strSeries;
    strSeries.Format("%s%d", ".", nSeries);
    //
    if (pMint->LoadMint(strSeries.Get())) {
        if (pMint->VerifyMint(server_->m_nymServer)) // I don't verify the
                                                     // Mint's
        // expiration date here, just its
        // signature, ID, etc.
        { // (Expiry dates are enforced on tokens during deposit--and checked
            // against mint--
            // but expiry dates are only enforced on the Mint itself during a
            // withdrawal.)
            // It's a multimap now...
            // mintsMap_[INSTRUMENT_DEFINITION_ID_STR.Get()] = pMint;

            mintsMap_.insert(std::pair<std::string, Mint*>(
                INSTRUMENT_DEFINITION_ID_STR.Get(), pMint));

            return pMint;
        }
        else {
            Log::vError(
                "Error verifying Mint in Transactor::getMint:\n%s%s%s\n",
                szFoldername, Log::PathSeparator(), szFilename);
        }
    }
    else {
        Log::vError("Error loading Mint in Transactor::getMint:\n%s%s%s\n",
                    szFoldername, Log::PathSeparator(), szFilename);
    }

    if (nullptr != pMint) delete pMint;
    pMint = nullptr;

    return nullptr;
}

} // namespace opentxs
