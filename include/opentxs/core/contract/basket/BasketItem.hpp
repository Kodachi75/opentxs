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

#ifndef OPENTXS_BASKET_BASKETITEM_HPP
#define OPENTXS_BASKET_BASKETITEM_HPP

#include <opentxs/core/Identifier.hpp>

#include <deque>

namespace opentxs
{

class BasketItem;

typedef std::deque<BasketItem*> dequeOfBasketItems;

class BasketItem
{
public:
    Identifier SUB_CONTRACT_ID;
    Identifier SUB_ACCOUNT_ID;

    int64_t lMinimumTransferAmount = 0;

    // lClosingTransactionNo:
    // Used when EXCHANGING a basket (NOT USED when first creating one.)
    // A basketReceipt must be dropped into each asset account during
    // an exchange, to account for the change in balance. Until that
    // receipt is accepted, lClosingTransactionNo will remain open as
    // an issued transaction number (an open transaction) on that Nym.
    // (One must be supplied for EACH asset account during an exchange.)
    //
    int64_t lClosingTransactionNo = 0;

    BasketItem() = default;
    ~BasketItem() = default;
};

} // namespace opentxs

#endif // OPENTXS_BASKET_BASKETITEM_HPP
