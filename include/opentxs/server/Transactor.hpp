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

#ifndef OPENTXS_SERVER_TRANSACTOR_HPP
#define OPENTXS_SERVER_TRANSACTOR_HPP

#include <opentxs/core/AccountList.hpp>
#include <string>
#include <map>
#include <memory>
#include <cstdint>

namespace opentxs
{

class Mint;
class OTServer;
class Nym;
class Identifier;
class Account;
class MainFile;

class Transactor
{
    friend class MainFile;

public:
    explicit Transactor(OTServer* server);
    ~Transactor();

    bool issueNextTransactionNumber(int64_t& txNumber);
    bool issueNextTransactionNumberToNym(Nym& nym, int64_t& txNumber);
    bool verifyTransactionNumber(Nym& nym, const int64_t& transactionNumber);
    bool removeTransactionNumber(Nym& nym, const int64_t& transactionNumber,
                                 bool save = false);
    bool removeIssuedNumber(Nym& nym, const int64_t& transactionNumber,
                            bool save = false);

    int64_t transactionNumber() const
    {
        return transactionNumber_;
    }

    void transactionNumber(int64_t value)
    {
        transactionNumber_ = value;
    }

    bool addBasketAccountID(const Identifier& basketId,
                            const Identifier& basketAccountId,
                            const Identifier& basketContractId);
    bool lookupBasketAccountID(const Identifier& basketId,
                               Identifier& basketAccountId);

    bool lookupBasketAccountIDByContractID(const Identifier& basketContractId,
                                           Identifier& basketAccountId);
    bool lookupBasketContractIDByAccountID(const Identifier& basketAccountId,
                                           Identifier& basketContractId);

    // Whenever the server issues a voucher (like a cashier's cheque), it puts
    // the funds in one
    // of these voucher accounts (one for each instrument definition ID). Then
    // it issues
    // the cheque from the
    // same account.
    // TODO: also should save the cheque itself to a folder, where the folder is
    // named based on the date
    // that the cheque will expire.  This way, the server operator can go back
    // later, or have a script,
    // to retrieve the cheques from the expired folders, and total them. The
    // server operator is free to
    // remove that total from the Voucher Account once the cheque has expired:
    // it is his money now.
    std::shared_ptr<Account> getVoucherAccount(
        const Identifier& instrumentDefinitionID);

    // Each asset contract has its own series of Mints
    Mint* getMint(const Identifier& instrumentDefinitionID,
                  int32_t seriesCount);

private:
    // Why does the map of mints use multimap instead of map?
    // Because there might be multiple valid mints for the same instrument
    // definition.
    // Perhaps I am redeeming tokens from the previous series, which have not
    // yet expired.
    // Only tokens from the new series are being issued today, but tokens from
    // the previous series are still good until their own expiration date, which
    // is coming up soon.
    // Therefore the server manages different mints for the same instrument
    // definition, and
    // since the instrument definition is the key in the multimap, we don't want
    // to
    // accidentally remove one from the list every time another is added. Thus
    // multimap is employed.
    typedef std::multimap<std::string, Mint*> MintsMap;
    typedef std::map<std::string, std::string> BasketsMap;

private:
    // This stores the last VALID AND ISSUED transaction number.
    int64_t transactionNumber_;
    // maps basketId with basketAccountId
    BasketsMap idToBasketMap_;
    // basket issuer account ID, which is *different* on each server, using the
    // Basket Currency's ID, which is the *same* on every server.)
    // Need a way to look up a Basket Account ID using its Contract ID
    BasketsMap contractIdToBasketAccountId_;
    // The list of voucher accounts (see GetVoucherAccount below for details)
    AccountList voucherAccounts_;
    // The mints for each instrument definition.
    MintsMap mintsMap_;

    OTServer* server_; // TODO: remove later when feasible
};

} // namespace opentxs

#endif // OPENTXS_SERVER_TRANSACTOR_HPP
