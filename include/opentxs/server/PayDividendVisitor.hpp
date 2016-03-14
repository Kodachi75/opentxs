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

#ifndef OPENTXS_SERVER_ACCTFUNCTOR_PAYDIVIDEND_HPP
#define OPENTXS_SERVER_ACCTFUNCTOR_PAYDIVIDEND_HPP

#include <opentxs/core/AccountVisitor.hpp>

#include <cstdint>

namespace opentxs
{

class Account;
class Identifier;
class OTServer;
class String;

// Note: from OTUnitDefinition.h and .cpp.
// This is a subclass of AccountVisitor, which is used whenever OTUnitDefinition
// needs to
// loop through all the accounts for a given instrument definition (its own.)
// This subclass
// needs to
// call OTServer method to do its job, so it can't be defined in otlib, but must
// be defined
// here in otserver (so it can see the methods that it needs...)
//
class PayDividendVisitor : public AccountVisitor
{
    Identifier* m_pNymID;
    Identifier* m_pPayoutInstrumentDefinitionID;
    Identifier* m_pVoucherAcctID;
    String* m_pstrMemo;  // contains the original payDividend item from the
                         // payDividend transaction request. (Stored in the
                         // memo field for each voucher.)
    OTServer* m_pServer; // no need to cleanup. It's here for convenience only.
    int64_t m_lPayoutPerShare;
    int64_t m_lAmountPaidOut;  // as we pay each voucher out, we keep a running
                               // count.
    int64_t m_lAmountReturned; // as we pay each voucher out, we keep a running
                               // count.

public:
    PayDividendVisitor(const Identifier& theNotaryID,
                       const Identifier& theNymID,
                       const Identifier& thePayoutInstrumentDefinitionID,
                       const Identifier& theVoucherAcctID,
                       const String& strMemo, OTServer& theServer,
                       int64_t lPayoutPerShare,
                       mapOfAccounts* pLoadedAccounts = nullptr);
    virtual ~PayDividendVisitor();

    Identifier* GetNymID()
    {
        return m_pNymID;
    }
    Identifier* GetPayoutInstrumentDefinitionID()
    {
        return m_pPayoutInstrumentDefinitionID;
    }
    Identifier* GetVoucherAcctID()
    {
        return m_pVoucherAcctID;
    }
    String* GetMemo()
    {
        return m_pstrMemo;
    }
    OTServer* GetServer()
    {
        return m_pServer;
    }
    int64_t GetPayoutPerShare()
    {
        return m_lPayoutPerShare;
    }
    int64_t GetAmountPaidOut()
    {
        return m_lAmountPaidOut;
    }
    int64_t GetAmountReturned()
    {
        return m_lAmountReturned;
    }

    virtual bool Trigger(Account& theAccount);
};

} // namespace opentxs

#endif // OPENTXS_SERVER_ACCTFUNCTOR_PAYDIVIDEND_HPP
