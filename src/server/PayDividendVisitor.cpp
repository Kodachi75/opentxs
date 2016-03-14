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

#include <opentxs/server/PayDividendVisitor.hpp>
#include <opentxs/server/OTServer.hpp>

#include <opentxs/core/Account.hpp>
#include <opentxs/core/Cheque.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/String.hpp>
#include <opentxs/ext/OTPayment.hpp>

namespace opentxs
{

PayDividendVisitor::PayDividendVisitor(
    const Identifier& theNotaryID, const Identifier& theNymID,
    const Identifier& thePayoutInstrumentDefinitionID,
    const Identifier& theVoucherAcctID, const String& strMemo,
    OTServer& theServer, int64_t lPayoutPerShare,
    mapOfAccounts* pLoadedAccounts)
    : AccountVisitor(theNotaryID, pLoadedAccounts)
    , m_pNymID(new Identifier(theNymID))
    , m_pPayoutInstrumentDefinitionID(
          new Identifier(thePayoutInstrumentDefinitionID))
    , m_pVoucherAcctID(new Identifier(theVoucherAcctID))
    , m_pstrMemo(new String(strMemo))
    , m_pServer(&theServer)
    , m_lPayoutPerShare(lPayoutPerShare)
    , m_lAmountPaidOut(0)
    , m_lAmountReturned(0)
{
}

PayDividendVisitor::~PayDividendVisitor()
{
    if (nullptr != m_pNymID) delete m_pNymID;
    m_pNymID = nullptr;
    if (nullptr != m_pPayoutInstrumentDefinitionID)
        delete m_pPayoutInstrumentDefinitionID;
    m_pPayoutInstrumentDefinitionID = nullptr;
    if (nullptr != m_pVoucherAcctID) delete m_pVoucherAcctID;
    m_pVoucherAcctID = nullptr;
    if (nullptr != m_pstrMemo) delete m_pstrMemo;
    m_pstrMemo = nullptr;
    m_pServer = nullptr; // don't delete this one (I don't own it.)
    m_lPayoutPerShare = 0;
    m_lAmountPaidOut = 0;
    m_lAmountReturned = 0;
}

// For each "user" account of a specific instrument definition, this function
// is called in order to pay a dividend to the Nym who owns that account.

// PayDividendVisitor::Trigger() is used in
// OTUnitDefinition::VisitAccountRecords()
// cppcheck-suppress unusedFunction
bool PayDividendVisitor::Trigger(Account& theSharesAccount) // theSharesAccount
                                                            // is, say, a Pepsi
                                                            // shares
// account.  Here, we'll send a dollars voucher
// to its owner.
{
    const int64_t lPayoutAmount =
        (theSharesAccount.GetBalance() * GetPayoutPerShare());

    if (lPayoutAmount <= 0) {
        Log::Output(0, "PayDividendVisitor::Trigger: nothing to pay, "
                       "since this account owns no shares. (Returning "
                       "true.)");
        return true; // nothing to pay, since this account owns no shares.
                     // Success!
    }
    OT_ASSERT(nullptr != GetNotaryID());
    const Identifier& theNotaryID = *(GetNotaryID());
    OT_ASSERT(nullptr != GetPayoutInstrumentDefinitionID());
    const Identifier& thePayoutInstrumentDefinitionID =
        *(GetPayoutInstrumentDefinitionID());
    OT_ASSERT(nullptr != GetVoucherAcctID());
    const Identifier& theVoucherAcctID = *(GetVoucherAcctID());
    OT_ASSERT(nullptr != GetServer());
    OTServer& theServer = *(GetServer());
    Nym& theServerNym = const_cast<Nym&>(theServer.GetServerNym());
    const Identifier theServerNymID(theServerNym);
    const Identifier& RECIPIENT_ID = theSharesAccount.GetNymID();
    OT_ASSERT(nullptr != GetNymID());
    const Identifier& theSenderNymID = *(GetNymID());
    OT_ASSERT(nullptr != GetMemo());
    const String& strMemo = *(GetMemo());
    // Note: theSenderNymID is the originator of the Dividend Payout.
    // However, all the actual vouchers will be from "the server Nym" and
    // not from theSenderNymID. So then why is it even here? Because anytime
    // there's an error, the server will send to theSenderNymID instead of
    // RECIPIENT_ID (so the original sender can have his money back, instead of
    // just having it get lost in the ether.)
    bool bReturnValue = false;

    Cheque theVoucher(theNotaryID, thePayoutInstrumentDefinitionID);

    // 10 minutes ==    600 Seconds
    // 1 hour    ==     3600 Seconds
    // 1 day    ==    86400 Seconds
    // 30 days    ==  2592000 Seconds
    // 3 months ==  7776000 Seconds
    // 6 months == 15552000 Seconds

    const time64_t VALID_FROM =
        OTTimeGetCurrentTime(); // This time is set to TODAY NOW
    const time64_t VALID_TO = OTTimeAddTimeInterval(
        VALID_FROM, OTTimeGetSecondsFromTime(
                        OT_TIME_SIX_MONTHS_IN_SECONDS)); // This time occurs in
                                                         // 180 days (6 months).
                                                         // Todo hardcoding.

    int64_t lNewTransactionNumber = 0;

    bool bGotNextTransNum =
        theServer.transactor_.issueNextTransactionNumberToNym(
            theServerNym, lNewTransactionNumber); // We save the transaction
    // number on the server Nym (normally we'd discard it) because
    // when the cheque is deposited, the server nym, as the owner of
    // the voucher account, needs to verify the transaction # on the
    // cheque (to prevent double-spending of cheques.)
    if (bGotNextTransNum) {
        const bool bIssueVoucher = theVoucher.IssueCheque(
            lPayoutAmount,         // The amount of the cheque.
            lNewTransactionNumber, // Requiring a transaction number prevents
                                   // double-spending of cheques.
            VALID_FROM, // The expiration date (valid from/to dates) of the
                        // cheque
            VALID_TO, // Vouchers are automatically starting today and lasting 6
                      // months.
            theVoucherAcctID, // The asset account the cheque is drawn on.
            theServerNymID,   // Nym ID of the sender (in this case the server
                              // nym.)
            strMemo, // Optional memo field. Includes item note and request
                     // memo.
            &RECIPIENT_ID);

        // All account crediting / debiting happens in the caller, in OTServer.
        //    (AND it happens only ONCE, to cover ALL vouchers.)
        // Then in here, the voucher either gets send to the recipient, or if
        // error, sent back home to
        // the issuer Nym. (ALL the funds are removed, then the vouchers are
        // sent one way or the other.)
        // Any returned vouchers, obviously serve to notify the dividend payer
        // of where the errors were
        // (as well as give him the opportunity to get his money back.)
        //
        bool bSent = false;
        if (bIssueVoucher) {
            // All this does is set the voucher's internal contract string to
            // "VOUCHER" instead of "CHEQUE". We also set the server itself as
            // the remitter, which is unusual for vouchers, but necessary in the
            // case of dividends.
            //
            theVoucher.SetAsVoucher(theServerNymID, theVoucherAcctID);
            theVoucher.SignContract(theServerNym);
            theVoucher.SaveContract();

            // Send the voucher to the payments inbox of the recipient.
            //
            const String strVoucher(theVoucher);
            OTPayment thePayment(strVoucher);

            // calls DropMessageToNymbox
            bSent = theServer.SendInstrumentToNym(
                theNotaryID, theServerNymID,          // sender nym
                RECIPIENT_ID,                         // recipient nym
                nullptr, &thePayment, "payDividend"); // todo: hardcoding.
            bReturnValue = bSent;                     // <======= RETURN VALUE.
            if (bSent)
                m_lAmountPaidOut +=
                    lPayoutAmount; // At the end of iterating all accounts, if
                                   // m_lAmountPaidOut is less than
                                   // lTotalPayoutAmount, then we return to rest
                                   // to the sender.
        }
        else {
            const String strPayoutInstrumentDefinitionID(
                thePayoutInstrumentDefinitionID),
                strRecipientNymID(RECIPIENT_ID);
            Log::vError("PayDividendVisitor::Trigger: ERROR failed "
                        "issuing voucher (to send to dividend payout "
                        "recipient.) "
                        "WAS TRYING TO PAY %" PRId64
                        " of instrument definition %s to Nym %s.\n",
                        lPayoutAmount, strPayoutInstrumentDefinitionID.Get(),
                        strRecipientNymID.Get());
        }
        // If we didn't send it, then we need to return the funds to where they
        // came from.
        //
        if (!bSent) {
            Cheque theReturnVoucher(theNotaryID,
                                    thePayoutInstrumentDefinitionID);

            const bool bIssueReturnVoucher = theReturnVoucher.IssueCheque(
                lPayoutAmount,         // The amount of the cheque.
                lNewTransactionNumber, // Requiring a transaction number
                                       // prevents double-spending of cheques.
                VALID_FROM, // The expiration date (valid from/to dates) of the
                            // cheque
                VALID_TO,   // Vouchers are automatically starting today and
                            // lasting 6 months.
                theVoucherAcctID, // The asset account the cheque is drawn on.
                theServerNymID,   // Nym ID of the sender (in this case the
                                  // server nym.)
                strMemo, // Optional memo field. Includes item note and request
                         // memo.
                &theSenderNymID); // We're returning the money to its original
                                  // sender.
            if (bIssueReturnVoucher) {
                // All this does is set the voucher's internal contract string
                // to
                // "VOUCHER" instead of "CHEQUE".
                //
                theReturnVoucher.SetAsVoucher(theServerNymID, theVoucherAcctID);
                theReturnVoucher.SignContract(theServerNym);
                theReturnVoucher.SaveContract();

                // Return the voucher back to the payments inbox of the original
                // sender.
                //
                const String strReturnVoucher(theReturnVoucher);
                OTPayment theReturnPayment(strReturnVoucher);

                // calls DropMessageToNymbox
                bSent = theServer.SendInstrumentToNym(
                    theNotaryID, theServerNymID, // sender nym
                    theSenderNymID, // recipient nym (original sender.)
                    nullptr, &theReturnPayment,
                    "payDividend"); // todo: hardcoding.
                if (bSent)
                    m_lAmountReturned +=
                        lPayoutAmount; // At the end of iterating all accounts,
                                       // if m_lAmountPaidOut+m_lAmountReturned
                                       // is less than lTotalPayoutAmount, then
                                       // we return the rest to the sender.
            }
            else {
                const String strPayoutInstrumentDefinitionID(
                    thePayoutInstrumentDefinitionID),
                    strSenderNymID(theSenderNymID);
                Log::vError("PayDividendVisitor::Trigger: ERROR "
                            "failed issuing voucher (to return back to "
                            "the dividend payout initiator, after a failed "
                            "payment attempt to the originally intended "
                            "recipient.) WAS TRYING TO PAY %" PRId64
                            " of instrument definition "
                            "%s to Nym %s.\n",
                            lPayoutAmount,
                            strPayoutInstrumentDefinitionID.Get(),
                            strSenderNymID.Get());
            }
        }  // if !bSent
    }
    else // !bGotNextTransNum
    {
        const String strPayoutInstrumentDefinitionID(
            thePayoutInstrumentDefinitionID),
            strRecipientNymID(RECIPIENT_ID);
        Log::vError(
            "PayDividendVisitor::Trigger: ERROR!! Failed issuing next "
            "transaction "
            "number while trying to send a voucher (while paying dividends.) "
            "WAS TRYING TO PAY %" PRId64
            " of instrument definition %s to Nym %s.\n",
            lPayoutAmount, strPayoutInstrumentDefinitionID.Get(),
            strRecipientNymID.Get());
    }

    return bReturnValue;
}

} // namespace opentxs
