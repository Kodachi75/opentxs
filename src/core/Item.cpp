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

#include <opentxs/core/Item.hpp>
#include <opentxs/core/Account.hpp>
#include <opentxs/core/Cheque.hpp>
#include <opentxs/core/Ledger.hpp>
#include <opentxs/core/util/Tag.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/Nym.hpp>
#include <opentxs/core/OTStorage.hpp>

#include <irrxml/irrXML.hpp>
#include <cstring>

#include <memory>

// Server-side.
//
// By the time this is called, I know that the item, AND this balance item (this)
// both have the correct user id, server id, account id, and transaction id, and
// they have been signed properly by the owner.
//
// So what do I need to verify in this function?
//
// -- That the transactions on THE_NYM (server-side), minus the current
// transaction number being processed, are all still there.
// -- If theMessageNym is missing certain numbers that I expected to find on
// him, that means he is trying to trick the server into signing a new agreement
// where he is no longer responsible for those numbers. They must all be there.
// -- If theMessageNym has ADDED certain numbers that I DIDN'T expect to find on
// him, then he's trying to trick me into allowing him to add those numbers to his
// receipt -- OR it could mean that certain numbers were already removed on my side
// (such as the opening # for a cron item like a market  offer that has already
// been closed), but the client-side isn't aware of this yet, and so he is trying
// to sign off on formerly-good numbers that have since expired.  This shouldn't
// happen IF the client has been properly notified about these numbers before
// sending his request.  Such notifications are dropped into the Nymbox AND related
// asset account inboxes.
//

namespace opentxs
{

bool Item::VerifyTransactionStatement(Nym& THE_NYM,
                                      OTTransaction& TARGET_TRANSACTION,
                                      bool bIsRealTransaction) // Sometimes the trans#
                                                               // is 0 (like when processing Nymbox)
{
    if (GetType() != Item::transactionStatement) {
        otOut << __FUNCTION__
              << ": wrong item type. Expected OTItem::transactionStatement.\n";
        return false;
    }

    //
    // So if the caller was planning to remove a number, or clear a receipt from
    // the inbox, he'll have to do
    // so first before calling this function, and then ADD IT AGAIN if this
    // function fails.  (Because the new
    // Balance Agreement is always the user signing WHAT THE NEW VERSION WILL BE
    // AFTER THE TRANSACTION IS PROCESSED.)
    //
    const String NOTARY_ID(GetPurportedNotaryID());

    Nym theRemovedNym;

    if (bIsRealTransaction) // Sometimes my "transaction number" is 0 since
                            // we're accepting numbers from the Nymbox (which is
                            // done by message, not transaction.)
    { //  In such cases, there's no point in checking the server-side to "make
        // sure it has number 0!" (because it won't.)
        bool bIWasFound =
            THE_NYM.VerifyIssuedNum(NOTARY_ID, GetTransactionNum());

        if (!bIWasFound) {
            otOut << __FUNCTION__ << ": Transaction# (" << GetTransactionNum()
                  << ") doesn't appear on Nym's issued list.\n";
            return false;
        }

        // In the case that this is a real transaction, it must be a
        // cancelCronItem, payment plan or
        // market offer (since the other transaction types require a balance
        // statement, not a transaction
        // statement.) Also this might not be a transaction at all, but in that
        // case we won't enter this
        // block anyway.
        //
        switch (TARGET_TRANSACTION.GetType()) {
        // In the case of cancelCronItem(), we'd expect, if success, the number
        // would be removed, so we have
        // to remove it now, to simulate success for the verification. Then we
        // add it again afterwards, before
        // returning.
        //
        case OTTransaction::cancelCronItem:
            // Only adding it to theRemovedNym here since VerifyIssuedNum() is
            // called just above.
            // (Don't want to "add it back" if it wasn't there in the first
            // place!)
            //
            if (THE_NYM.RemoveIssuedNum(NOTARY_ID,
                                        GetTransactionNum())) // doesn't save.
                theRemovedNym.AddIssuedNum(NOTARY_ID, GetTransactionNum());
            else
                otOut << "OTItem::VerifyTransactionStatemen: Expected THE_NYM "
                         "to have trans# " << GetTransactionNum()
                      << " but didn't find it.\n";
            break;

        // IN the case of the offer/plan, we do NOT want to remove from issued
        // list. That only happens when
        // the plan or offer is removed from Cron and closed. As the plan or
        // offer continues processing,
        // the user is responsible for its main transaction number until he
        // signs off on final closing,
        // after many receipts have potentially been received.
        //
        case OTTransaction::marketOffer:
        case OTTransaction::paymentPlan:
        case OTTransaction::smartContract:
            //              THE_NYM.RemoveIssuedNum(NOTARY_ID,
            // GetTransactionNum()); // commented out, explained just
            // above.
            break;
        default:
            otErr << "OTItem::VerifyTransactionStatement: Unexpected "
                     "transaction type.\n";
            break;
        }

        // Client side will NOT remove from issued list in this case (market
        // offer, payment plan, which are
        // the only transactions that use a transactionStatement, which is
        // otherwise used for Nymbox.)
    }

    // VERIFY that the Nyms have a matching list of transaction numbers...

    bool bSuccess = false;

    String strMessageNym;

    GetAttachment(strMessageNym);
    Nym theMessageNym;

    if ((strMessageNym.GetLength() > 2) &&
        theMessageNym.LoadNymFromString(strMessageNym)) {
        // If success, I know the server-side copy of the user's Nym (THE_NYM)
        // has the same number
        // of transactions as the message nym, and that EVERY ONE OF THEM was
        // found individually.
        //
        bSuccess = THE_NYM.VerifyIssuedNumbersOnNym(
            theMessageNym); // <==== ************************************
    }

    // NOW let's set things back how they were before, so we can RETURN.
    //
    if (bIsRealTransaction) {
        switch (TARGET_TRANSACTION.GetType()) {
        case OTTransaction::cancelCronItem:
            // Should only actually iterate once, in this case.
            for (int32_t i = 0;
                 i < theRemovedNym.GetIssuedNumCount(GetPurportedNotaryID());
                 i++) {
                int64_t lTemp =
                    theRemovedNym.GetIssuedNum(GetPurportedNotaryID(), i);

                if (i > 0)
                    otErr << "OTItem::VerifyTransactionStatement: THIS SHOULD "
                             "NOT HAPPEN.\n";
                else if (false ==
                         THE_NYM.AddIssuedNum(NOTARY_ID,
                                              lTemp)) // doesn't save.
                    otErr << "Failed adding issued number back to THE_NYM in "
                             "OTItem::VerifyTransactionStatement.\n";
            }
            break;

        case OTTransaction::marketOffer:
        case OTTransaction::paymentPlan:
        case OTTransaction::smartContract:
        default:
            //              THE_NYM.RemoveIssuedNum(NOTARY_ID,
            // GetTransactionNum()); // commented out, explained just
            // above.
            break;
        }
    }

    // Might want to consider saving the Nym here.
    // Also want to save the latest signed receipt, since it VERIFIES.
    // Or maybe let caller decide?

    return bSuccess;
}

// Server-side.
//
// By the time this is called, I know that the item, AND this balance item
// (this)
// both have the correct user id, server id, account id, and transaction id, and
// they have been signed properly by the owner.
//
// So what do I need to verify in this function?
//
// 1) That THE_ACCOUNT.GetBalance() + lActualAdjustment equals the amount in
// GetAmount().
//
// 2) That the inbox transactions and outbox transactions match up to the list
// of sub-items
//    on THIS balance item.
//
// 3) That the transactions on the Nym, minus the current transaction number
// being processed,
//    are all still there.
//
bool Item::VerifyBalanceStatement(int64_t lActualAdjustment, Nym& THE_NYM,
                                  Ledger& THE_INBOX, Ledger& THE_OUTBOX,
                                  const Account& THE_ACCOUNT,
                                  OTTransaction& TARGET_TRANSACTION,
                                  int64_t lOutboxTrnsNum) // Only used in the
                                                          // case of transfer,
                                                          // where the user
{ // doesn't know the outbox trans# in advance, so he sends
    if (GetType() != Item::balanceStatement) // a dummy number (currently '1')
                                             // which we verify against
    { // the actual outbox trans# successfully, only in that special case.
        otOut << "OTItem::" << __FUNCTION__ << ": wrong item type.\n";
        return false;
    }

    // We need to verify:
    //
    // 1) That THE_ACCOUNT.GetBalance() + lActualAdjustment equals the amount in
    // GetAmount().

    if ((THE_ACCOUNT.GetBalance() + lActualAdjustment) !=
        GetAmount()) // GetAmount() contains what the balance WOULD
                     // be AFTER successful transaction.
    {
        otOut << "OTItem::" << __FUNCTION__
              << ": This balance statement has a value of " << GetAmount()
              << ", but expected "
              << (THE_ACCOUNT.GetBalance() + lActualAdjustment)
              << ". "
                 "(Acct balance of " << THE_ACCOUNT.GetBalance()
              << " plus actualAdjustment of " << lActualAdjustment << ".)\n";
        return false;
    }

    // 2) That the inbox transactions and outbox transactions match up to the
    // list of sub-items
    //    on THIS balance item.

    int32_t nInboxItemCount = 0, nOutboxItemCount = 0;

    const char* szInbox = "Inbox";
    const char* szOutbox = "Outbox";

    const char* pszLedgerType = nullptr;

    //    otWarn << "OTItem::VerifyBalanceStatement: (ENTERING LOOP)... INBOX
    // COUNT: %d\n"
    //                   "# of inbox/outbox items on this balance statement:
    // %d\n",
    //                   THE_INBOX.GetTransactionCount(), GetItemCount());

    for (int32_t i = 0; i < GetItemCount(); i++) {
        Item* pSubItem = GetItem(i);
        OT_ASSERT(nullptr != pSubItem);
        //      otWarn << "OTItem::VerifyBalanceStatement: TOP OF LOOP (through
        // sub-items).......\n");

        int64_t lReceiptAmountMultiplier = 1; // needed for outbox items.

        Ledger* pLedger = nullptr;

        switch (pSubItem->GetType()) {
        case Item::voucherReceipt:
        case Item::chequeReceipt:
        case Item::marketReceipt:
        case Item::paymentReceipt:
        case Item::transferReceipt:
        case Item::basketReceipt:
        case Item::finalReceipt:
            nInboxItemCount++;
            pLedger = &THE_INBOX;
            pszLedgerType = szInbox;

        //              otWarn << "OTItem::VerifyBalanceStatement: Subitem is
        // Inbox receipt item (NOT pending transfer)....\n");

        case Item::transfer:
            break;
        default: {
            String strItemType;
            GetTypeString(strItemType);
            otWarn << "OTItem::" << __FUNCTION__ << ": Ignoring " << strItemType
                   << " item in balance statement while verifying it against "
                      "inbox.\n";
        }
            continue;
        }

        switch (pSubItem->GetType()) {
        case Item::transfer:
            if (pSubItem->GetAmount() < 0) // it's an outbox item
            {
                //                  otWarn << "OTItem::VerifyBalanceStatement:
                // Subitem is pending transfer (in outbox)....\n");

                lReceiptAmountMultiplier =
                    -1; // transfers out always reduce your balance.
                nOutboxItemCount++;
                pLedger = &THE_OUTBOX;
                pszLedgerType = szOutbox;
            }
            else {
                //                  otWarn << "OTItem::VerifyBalanceStatement:
                // Subitem is pending transfer (in inbox)....\n");

                lReceiptAmountMultiplier =
                    1; // transfers in always increase your balance.
                nInboxItemCount++;
                pLedger = &THE_INBOX;
                pszLedgerType = szInbox;
            }
            break;
        case Item::finalReceipt:
        // Here: If there is a finalReceipt on this balance statement, then ALL
        // the other
        // related receipts in the inbox (with same "reference to" value) had
        // better ALSO
        // be on the same balance statement!

        // HMM that is true, but NOT HERE... That's only true when PROCESSING
        // the final Receipt
        // from the inbox (in that case, all the marketReceipts must also be
        // processed with it.)
        // But here, I am looping through the inbox report, and there happens to
        // be a finalReceipt
        // on it. (Which doesn't mean necessarily that it's being processed
        // out...)
        case Item::basketReceipt:

        case Item::transferReceipt:
        case Item::voucherReceipt:
        case Item::chequeReceipt:
        case Item::marketReceipt:
        case Item::paymentReceipt:
            lReceiptAmountMultiplier = 1;
            break;
        default:
            otErr << "OTItem::" << __FUNCTION__
                  << ": Bad Subitem type (SHOULD NEVER HAPPEN)....\n";

            continue; // This will never happen, due to the first continue above
                      // in the first switch.
        }

        OTTransaction* pTransaction = nullptr;

        // In the special case of account transfer, the user has put an outbox
        // transaction
        // into his balance agreement with the special number '1', since he has
        // no idea what
        // actual number will be generated on the server side (for the outbox)
        // when his
        // message is received by the server.
        //
        // When that happens (ONLY in account transfer) then lOutboxTrnsNum will
        // be passed
        // in with the new transaction number chosen by the server (a real
        // number, like 18736
        // or whatever, instead of the default of 0 that will otherwise be
        // passed in here.)
        //
        // Therefore, if lOutboxTrnsNum is larger than 0, AND if we're on an
        // outbox item,
        // then we can expect lOutboxTrnsNum to contain an actual transaction
        // number, and
        // we can expect there is a CHANCE that the sub-item will be trans# 1.
        // (It might
        // NOT be number 1, since there may be other outbox items-we're looping
        // through them
        // right now in this block.) So we'll check to see if this is the '1'
        // and if so,
        // we'll look up pTransaction from the outbox using the real transaction
        // number,
        // instead of '1' which of course would not find it (since the version
        // in the ledger
        // contains the ACTUAL number now, since the server just issued it.)
        //
        if ((lOutboxTrnsNum > 0) && (&THE_OUTBOX == pLedger) &&
            (pSubItem->GetTransactionNum() == 1)) // TODO use a constant for
                                                  // this 1.
        {
            otLog3 << "OTItem::" << __FUNCTION__
                   << ": Subitem is new Outbox Transaction... retrieving by "
                      "special ID: " << lOutboxTrnsNum << "\n";

            pTransaction = pLedger->GetTransaction(lOutboxTrnsNum);
        }
        else {
            otLog4 << "OTItem::" << __FUNCTION__
                   << ": Subitem is normal Transaction... retrieving by ID: "
                   << pSubItem->GetTransactionNum() << "\n";

            pTransaction =
                pLedger->GetTransaction(pSubItem->GetTransactionNum());
        }

        // Make sure that the transaction number of each sub-item is found
        // on the appropriate ledger (inbox or outbox).
        if (nullptr == pTransaction) {
            otOut << "OTItem::" << __FUNCTION__ << ": Expected "
                  << pszLedgerType << " transaction (serv " << lOutboxTrnsNum
                  << ", client " << pSubItem->GetTransactionNum()
                  << ") "
                     "not found. (Amount " << pSubItem->GetAmount() << ".)\n";
            return false;
        }
        // pTransaction is set below this point.

        if (pSubItem->GetReferenceToNum() !=
            pTransaction->GetReferenceToNum()) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") mismatch Reference Num: "
                  << pSubItem->GetReferenceToNum() << ", expected "
                  << pTransaction->GetReferenceToNum() << "\n";
            return false;
        }

        if (pSubItem->GetRawNumberOfOrigin() !=
            pTransaction->GetRawNumberOfOrigin()) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") mismatch Origin Num: "
                  << pSubItem->GetRawNumberOfOrigin() << ", expected "
                  << pTransaction->GetRawNumberOfOrigin() << "\n";

            // THE BELOW STUFF IS JUST FOR DEBUGGING PURPOSES.
            // ERASE IT.

            /*
            OTString strTempType;
            pSubItem->GetTypeString(strTempType);

            int64_t lTempAmount = pSubItem->GetAmount();

            OTIdentifier ACCOUNT_ID, NOTARY_ID, NYM_ID;

            ACCOUNT_ID = pSubItem->GetPurportedAccountID();
            NOTARY_ID  = pSubItem->GetPurportedNotaryID();
            NYM_ID    = pSubItem->GetNymID();

            const OTString strAccountID(ACCOUNT_ID), strNotaryID(NOTARY_ID),
            strNymID(NYM_ID);


            int64_t lTempNumOfOrigin = pSubItem->GetNumberOfOrigin();
            int64_t lTempTransNum    = pSubItem->GetTransactionNum();
            int64_t lTempRefNum      = pSubItem->GetReferenceToNum();
            int64_t lTempClosingNum  = pSubItem->GetClosingNum();


            const OTString strTrans(*pTransaction);
            otOut << "OTItem::%s: %s transaction (%" PRId64 ") mismatch Origin
            Num:
            %" PRId64 ", expected %" PRId64 "\n\nTRANSACTION:\n%s\n\n"
               "SubItem Type: %s  Amount: %" PRId64 "\nAccount: %s\nServer:
            %s\nUser: %s\n"
            " Number of Origin: %" PRId64 "\n Transaction Num: %" PRId64 "\n In
            Reference To: %" PRId64 "\n Closing Num: %d\n",
                           __FUNCTION__, pszLedgerType,
            pSubItem->GetTransactionNum(),
                           pSubItem->GetRawNumberOfOrigin(),
            pTransaction->GetRawNumberOfOrigin(),
                           strTrans.Get(),
                           strTempType.Get(), lTempAmount, strAccountID.Get(),
            strNotaryID.Get(), strNymID.Get(),
                           lTempNumOfOrigin, lTempTransNum, lTempRefNum,
            lTempClosingNum
                           );
             */
            return false;
        }

        int64_t lTransactionAmount = pTransaction->GetReceiptAmount();
        lTransactionAmount *= lReceiptAmountMultiplier;

        if (pSubItem->GetAmount() != lTransactionAmount) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") "
                     "amounts don't match: report amount is "
                  << pSubItem->GetAmount() << ", but expected "
                  << lTransactionAmount
                  << ". Trans Receipt Amt: " << pTransaction->GetReceiptAmount()
                  << " (GetAmount() == " << GetAmount() << ".)\n";
            return false;
        }

        if ((pSubItem->GetType() == Item::transfer) &&
            (pTransaction->GetType() != OTTransaction::pending)) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") wrong type. (transfer block)\n";
            return false;
        }

        if ((pSubItem->GetType() == Item::chequeReceipt) &&
            (pTransaction->GetType() != OTTransaction::chequeReceipt)) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") wrong type. (chequeReceipt block)\n";
            return false;
        }

        if ((pSubItem->GetType() == Item::voucherReceipt) &&
            (pTransaction->GetType() != OTTransaction::voucherReceipt)) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") wrong type. (voucherReceipt block)\n";
            return false;
        }

        if ((pSubItem->GetType() == Item::marketReceipt) &&
            (pTransaction->GetType() != OTTransaction::marketReceipt)) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") wrong type. (marketReceipt block)\n";
            return false;
        }

        if ((pSubItem->GetType() == Item::paymentReceipt) &&
            (pTransaction->GetType() != OTTransaction::paymentReceipt)) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") wrong type. (paymentReceipt block)\n";
            return false;
        }

        if ((pSubItem->GetType() == Item::transferReceipt) &&
            (pTransaction->GetType() != OTTransaction::transferReceipt)) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") wrong type. (transferReceipt block)\n";
            return false;
        }

        if ((pSubItem->GetType() == Item::basketReceipt) &&
            ((pTransaction->GetType() != OTTransaction::basketReceipt) ||
             (pSubItem->GetClosingNum() != pTransaction->GetClosingNum()))) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") wrong type or closing num ("
                  << pSubItem->GetClosingNum() << "). "
                                                  "(basketReceipt block)\n";
            return false;
        }

        if ((pSubItem->GetType() == Item::finalReceipt) &&
            ((pTransaction->GetType() != OTTransaction::finalReceipt) ||
             (pSubItem->GetClosingNum() != pTransaction->GetClosingNum()))) {
            otOut << "OTItem::" << __FUNCTION__ << ": " << pszLedgerType
                  << " transaction (" << pSubItem->GetTransactionNum()
                  << ") wrong type or closing num ("
                  << pSubItem->GetClosingNum() << "). "
                                                  "(finalReceipt block)\n";
            return false;
        }
    }

    // By this point, I have an accurate count of the inbox items, and outbox
    // items, represented
    // by this. let's compare those counts to the actual inbox and outbox on my
    // side:

    if ((nInboxItemCount != THE_INBOX.GetTransactionCount()) ||
        (nOutboxItemCount != THE_OUTBOX.GetTransactionCount())) {
        otOut << "OTItem::" << __FUNCTION__
              << ": Inbox or Outbox mismatch in expected transaction count.\n"
                 " --- THE_INBOX count: " << THE_INBOX.GetTransactionCount()
              << " --- THE_OUTBOX count: " << THE_OUTBOX.GetTransactionCount()
              << "\n"
                 "--- nInboxItemCount count: " << nInboxItemCount
              << " --- nOutboxItemCount count: " << nOutboxItemCount << "\n\n";

        return false;
    }

    // Now I KNOW that the inbox and outbox counts are the same, AND I know that
    // EVERY transaction number
    // on the balance item (this) was also found in the inbox or outbox,
    // wherever it was expected to be found.
    // I also know:
    // the amount was correct,
    // the "in reference to" number was correct,
    // and the type was correct.
    //
    // So if the caller was planning to remove a number, or clear a receipt from
    // the inbox, he'll have to do
    // so first before calling this function, and then ADD IT AGAIN if this
    // function fails.  (Because the new
    // Balance Agreement is always the user signing WHAT THE NEW VERSION WILL BE
    // AFTER THE TRANSACTION IS PROCESSED.
    // Thus, if the transaction fails to process, the action hasn't really
    // happened, so need to add it back again.)

    // 3) Also need to verify the transactions on the Nym, against the
    // transactions stored on this
    //    (in a message Nym attached to this.)  Check for presence of each, then
    // compare count, like above.

    Nym theRemovedNym;

    String NOTARY_ID(GetPurportedNotaryID());

    // GetTransactionNum() is the ID for this balance agreement, THUS it's also
    // the ID
    // for whatever actual transaction is being attempted. If that ID is not
    // verified as
    // on my issued list, then the whole transaction is invalid (not
    // authorized.)
    //
    bool bIWasFound = THE_NYM.VerifyIssuedNum(NOTARY_ID, GetTransactionNum());

    if (!bIWasFound) {
        otOut << "OTItem::" << __FUNCTION__ << ": Transaction has # that "
                                               "doesn't appear on Nym's issued "
                                               "list.\n";
        return false;
    }

    // BELOW THIS POINT, WE *KNOW* THE ISSUED NUM IS CURRENTLY ON THE LIST...
    //
    // (SO I CAN remove it and add it again, KNOWING that I'm never re-adding a
    // num that wasn't there in the first place.

    // For process inbox, deposit, and withdrawal, the client will remove from
    // issued list as soon as he
    // receives my acknowledgment OR rejection. He expects server (me) to
    // remove, so he signs a balance
    // agreement to that effect. (With the number removed from issued list.)
    //
    // Therefore, to verify the balance agreement, we remove it on our side as
    // well, so that they will match.
    // The picture thus formed is what would be correct assuming a successful
    // transaction. That way if
    // the transaction goes through, we have our signed receipt showing the new
    // state of things (without
    // which we would not permit the transaction to go through :)
    //
    // This allows the client side to then ACTUALLY remove the number when they
    // receive our response,
    // as well as permits me (server) to actually remove from issued list.
    //
    // If ANYTHING ELSE fails during this verify process (other than
    // processInbox, deposit, and withdraw)
    // then we have to ADD THE # AGAIN since we still don't have a valid
    // signature on that number. So
    // you'll see this code repeated a few times in reverse, down inside this
    // function. For example,
    //
    switch (TARGET_TRANSACTION.GetType()) {
    case OTTransaction::processInbox:
    case OTTransaction::withdrawal:
    case OTTransaction::deposit:
    case OTTransaction::payDividend:
    case OTTransaction::cancelCronItem:
    case OTTransaction::exchangeBasket:
        // We DID verify the issued num (above) but I'm still just being safe
        // here...
        // ... since theRemovedNym contains numbers being re-added, just wanna
        // make sure
        // they were there in the first place.
        //
        if (THE_NYM.RemoveIssuedNum(NOTARY_ID,
                                    GetTransactionNum())) // doesn't save.
            theRemovedNym.AddIssuedNum(NOTARY_ID, GetTransactionNum());
        break;

    case OTTransaction::transfer:
    case OTTransaction::marketOffer:
    case OTTransaction::paymentPlan:
    case OTTransaction::smartContract:
        // These, assuming success, do NOT remove an issued number. So no need
        // to anticipate setting up the list that way, to get a match.
        break;
    default:
        // Error
        otErr << "OTItem::" << __FUNCTION__
              << ": wrong target transaction type: "
              << TARGET_TRANSACTION.GetTypeString() << "\n";
        break;
    }
    int32_t nNumberOfTransactionNumbers1 = 0; // The Nym on this side
    int32_t nNumberOfTransactionNumbers2 = 0; // The Message Nym.

    String strMessageNym;

    // First, loop through the Nym on my side, and count how many numbers total
    // he has...
    //
    for (auto& it : THE_NYM.GetMapIssuedNum()) {
        std::string strNotaryID = it.first;
        dequeOfTransNums* pDeque = it.second;
        OT_ASSERT(nullptr != pDeque);

        const Identifier theNotaryID(strNotaryID.c_str());

        if (!(pDeque->empty()) && (theNotaryID == GetPurportedNotaryID())) {
            nNumberOfTransactionNumbers1 +=
                static_cast<int32_t>(pDeque->size());
            break; // There's only one, in this loop, that would/could/should
                   // match. (Therefore, break after finding it.)
        }
    } // for

    // Next, loop through theMessageNym, and count his numbers as well...
    // But ALSO verify that each one exists on THE_NYM, so that each individual
    // number is checked.
    GetAttachment(strMessageNym);
    Nym theMessageNym;

    if ((strMessageNym.GetLength() > 2) &&
        theMessageNym.LoadNymFromString(strMessageNym)) {
        for (auto& it : theMessageNym.GetMapIssuedNum()) {
            std::string strNotaryID = it.first;
            dequeOfTransNums* pDeque = it.second;
            OT_ASSERT(nullptr != pDeque);

            const Identifier theNotaryID(strNotaryID.c_str());
            const String OTstrNotaryID(theNotaryID);

            if (!(pDeque->empty()) && (theNotaryID == GetPurportedNotaryID())) {
                nNumberOfTransactionNumbers2 +=
                    static_cast<int32_t>(pDeque->size());

                for (uint32_t i = 0; i < pDeque->size(); i++) {
                    int64_t lTransactionNumber = pDeque->at(i);
                    if (false ==
                        THE_NYM.VerifyIssuedNum(OTstrNotaryID,
                                                lTransactionNumber)) // FAILURE
                    {
                        otOut << "OTItem::" << __FUNCTION__
                              << ": Issued transaction # " << lTransactionNumber
                              << " from Message Nym not found on this side.\n";

                        // I have to do this whenever I RETURN :-(
                        switch (TARGET_TRANSACTION.GetType()) {
                        case OTTransaction::processInbox:
                        case OTTransaction::withdrawal:
                        case OTTransaction::deposit:
                        case OTTransaction::payDividend:
                        case OTTransaction::cancelCronItem:
                        case OTTransaction::exchangeBasket:
                            // Should only actually iterate once, in this case.
                            for (int32_t j = 0;
                                 j < theRemovedNym.GetIssuedNumCount(
                                         GetPurportedNotaryID());
                                 j++) {
                                int64_t lTemp = theRemovedNym.GetIssuedNum(
                                    GetPurportedNotaryID(), j);

                                if (j > 0)
                                    otErr << "OTItem::" << __FUNCTION__
                                          << ": THIS SHOULD NOT HAPPEN.\n";
                                else if (false ==
                                         THE_NYM.AddIssuedNum(
                                             NOTARY_ID, lTemp)) // doesn't save.
                                    otErr << "OTItem::" << __FUNCTION__
                                          << ": Failed adding issued number "
                                             "back to THE_NYM.\n";
                            }
                            break;

                        case OTTransaction::transfer:
                        case OTTransaction::marketOffer:
                        case OTTransaction::paymentPlan:
                        case OTTransaction::smartContract:
                            break;
                        default:
                            // Error
                            otErr << "OTItem::" << __FUNCTION__
                                  << ": wrong target transaction type: "
                                  << TARGET_TRANSACTION.GetTypeString() << "\n";
                            break;
                        }

                        return false;
                    }
                }      // for (numbers for a specific server.)
                break; // Only one server ID should match, so we can break after
                       // finding it.
            }          // If the server ID matches
        }              // for (deques of numbers for each server)
    }

    // Finally, verify that the counts match...
    if (nNumberOfTransactionNumbers1 != nNumberOfTransactionNumbers2) {
        otOut << "OTItem::" << __FUNCTION__
              << ": Transaction # Count mismatch: "
              << nNumberOfTransactionNumbers1 << " and "
              << nNumberOfTransactionNumbers2 << "\n";

        // I have to do this whenever I RETURN :-(
        switch (TARGET_TRANSACTION.GetType()) {
        case OTTransaction::processInbox:
        case OTTransaction::withdrawal:
        case OTTransaction::deposit:
        case OTTransaction::payDividend:
        case OTTransaction::cancelCronItem:
        case OTTransaction::exchangeBasket:
            // Should only actually iterate once, in this case.
            for (int32_t i = 0;
                 i < theRemovedNym.GetIssuedNumCount(GetPurportedNotaryID());
                 i++) {
                int64_t lTemp =
                    theRemovedNym.GetIssuedNum(GetPurportedNotaryID(), i);

                if (i > 0)
                    otErr << "OTItem::" << __FUNCTION__
                          << ": THIS SHOULD NOT HAPPEN.\n";
                else if (false ==
                         THE_NYM.AddIssuedNum(NOTARY_ID,
                                              lTemp)) // doesn't save.
                    otErr << "OTItem::" << __FUNCTION__
                          << ": Failed adding issued number back to THE_NYM.\n";
            }
            break;

        case OTTransaction::transfer:
        case OTTransaction::marketOffer:
        case OTTransaction::paymentPlan:
        case OTTransaction::smartContract:
            break;
        default:
            // Error
            otErr << "OTItem::" << __FUNCTION__
                  << ": wrong target transaction type: "
                  << TARGET_TRANSACTION.GetTypeString() << "\n";
            break;
        }

        return false;
    }

    // By this point, I know the local Nym has the same number of transactions
    // as the message nym, and that
    // EVERY ONE OF THEM was found individually.

    // Might want to consider saving the Nym here.
    // Also want to save the latest signed receipt, since it VERIFIES.
    // Or maybe let caller decide?

    // I have to do this whenever I RETURN :-(
    // EVEN IF SUCCESS, we have only succeeded to verify the balance statement.
    // We must still go on to verify the transaction itself, and ONLY THEN will
    // we (possibly) remove the issued number from the list. And the decision
    // will
    // change from situation to situation, depending on the instrument.
    // Therefore I add it back here as well. We only fiddled with it in the
    // first place
    // in order to verify the balance statement. Done. So now let the other
    // pieces decide
    // their own logic from there.
    //
    switch (TARGET_TRANSACTION.GetType()) {
    case OTTransaction::processInbox:
    case OTTransaction::withdrawal:
    case OTTransaction::deposit:
    case OTTransaction::payDividend:
    case OTTransaction::cancelCronItem:
    case OTTransaction::exchangeBasket:
        // Should only actually iterate once, in this case.
        for (int32_t i = 0;
             i < theRemovedNym.GetIssuedNumCount(GetPurportedNotaryID()); i++) {
            int64_t lTemp =
                theRemovedNym.GetIssuedNum(GetPurportedNotaryID(), i);

            if (i > 0)
                otErr << "OTItem::" << __FUNCTION__
                      << ": THIS SHOULD NOT HAPPEN.\n";
            else if (false ==
                     THE_NYM.AddIssuedNum(NOTARY_ID, lTemp)) // doesn't save.
                otErr << "OTItem::" << __FUNCTION__
                      << ": Failed adding issued number back to THE_NYM.\n";
        }
        break;

    case OTTransaction::transfer:
    case OTTransaction::marketOffer:
    case OTTransaction::paymentPlan:
    case OTTransaction::smartContract:
        break;
    default:
        // Error
        otErr << "OTItem::" << __FUNCTION__
              << ": wrong target transaction type: "
              << TARGET_TRANSACTION.GetTypeString() << "\n";
        break;
    }

    return true;
}

// You have to allocate the item on the heap and then pass it in as a reference.
// OTTransaction will take care of it from there and will delete it in
// destructor.
void Item::AddItem(Item& theItem)
{
    m_listItems.push_back(&theItem);
}

// While processing a transaction, you may wish to query it for items of a
// certain type.
Item* Item::GetItem(int32_t nIndex)
{
    int32_t nTempIndex = (-1);

    for (auto& it : m_listItems) {
        Item* pItem = it;
        OT_ASSERT(nullptr != pItem);

        nTempIndex++; // first iteration this becomes 0 here.

        if (nTempIndex == nIndex) return pItem;
    }

    return nullptr;
}

// While processing an item, you may wish to query it for sub-items
Item* Item::GetItemByTransactionNum(int64_t lTransactionNumber)
{
    for (auto& it : m_listItems) {
        Item* pItem = it;
        OT_ASSERT(nullptr != pItem);

        if (pItem->GetTransactionNum() == lTransactionNumber) return pItem;
    }

    return nullptr;
}

// Count the number of items that are IN REFERENCE TO some transaction#.
//
// Might want to change this so that it only counts ACCEPTED receipts.
//
int32_t Item::GetItemCountInRefTo(int64_t lReference)
{
    int32_t nCount = 0;

    for (auto& it : m_listItems) {
        Item* pItem = it;
        OT_ASSERT(nullptr != pItem);

        if (pItem->GetReferenceToNum() == lReference) nCount++;
    }

    return nCount;
}

// The final receipt item MAY be present, and co-relates to others that share
// its "in reference to" value. (Others such as marketReceipts and
// paymentReceipts.)
//
Item* Item::GetFinalReceiptItemByReferenceNum(int64_t lReferenceNumber)
{
    for (auto& it : m_listItems) {
        Item* pItem = it;
        OT_ASSERT(nullptr != pItem);

        if (Item::finalReceipt != pItem->GetType()) continue;
        if (pItem->GetReferenceToNum() == lReferenceNumber) return pItem;
    }

    return nullptr;
}

// For "OTItem::acceptTransaction"
//
bool Item::AddBlankNumbersToItem(const NumList& theAddition)
{
    return m_Numlist.Add(theAddition);
}

// Need to know the transaction number of the ORIGINAL transaction? Call this.
// virtual
int64_t Item::GetNumberOfOrigin()
{

    if (0 == m_lNumberOfOrigin) {
        switch (GetType()) {
        case acceptPending: // this item is a client-side acceptance of a
                            // pending transfer
        case rejectPending: // this item is a client-side rejection of a pending
                            // transfer
        case acceptCronReceipt:  // this item is a client-side acceptance of a
                                 // cron receipt in his inbox.
        case acceptItemReceipt:  // this item is a client-side acceptance of an
                                 // item receipt in his inbox.
        case disputeCronReceipt: // this item is a client dispute of a cron
                                 // receipt in his inbox.
        case disputeItemReceipt: // this item is a client dispute of an item
                                 // receipt in his inbox.

        case acceptFinalReceipt:   // this item is a client-side acceptance of a
                                   // final receipt in his inbox. (All related
                                   // receipts must also be closed!)
        case acceptBasketReceipt:  // this item is a client-side acceptance of a
                                   // basket receipt in his inbox.
        case disputeFinalReceipt:  // this item is a client-side rejection of a
                                   // final receipt in his inbox. (All related
                                   // receipts must also be closed!)
        case disputeBasketReceipt: // this item is a client-side rejection of a
                                   // basket receipt in his inbox.

            otErr << __FUNCTION__ << ": In this case, you can't calculate the "
                                     "origin number, you must set it "
                                     "explicitly.\n";
            // Comment this out later so people can't use it to crash the
            // server:
            OT_FAIL_MSG("In this case, you can't calculate the origin number, "
                        "you must set it explicitly.");
            break;
        default:
            break;
        }

        CalculateNumberOfOrigin();
    }

    return m_lNumberOfOrigin;
}

// virtual
void Item::CalculateNumberOfOrigin()
{
    switch (GetType()) {
    case acceptTransaction:   // this item is a client-side acceptance of a
                              // transaction number (a blank) in my Nymbox
    case atAcceptTransaction: // server reply
    case acceptMessage: // this item is a client-side acceptance of a message in
                        // my Nymbox
    case atAcceptMessage: // server reply
    case acceptNotice:    // this item is a client-side acceptance of a server
                          // notification in my Nymbox
    case atAcceptNotice:  // server reply
    case replyNotice:   // server notice of a reply that nym should have already
                        // received as a response to a request. (Copy dropped in
                        // nymbox.)
    case successNotice: // server notice dropped into nymbox as result of a
                        // transaction# being successfully signed out.
    case notice: // server notice dropped into nymbox as result of a smart
                 // contract processing.
    case transferReceipt: // Currently don't create an OTItem for transfer
                          // receipt in inbox. Used only for inbox report.
    case chequeReceipt:   // Currently don't create an OTItem for cheque receipt
                          // in inbox. Used only for inbox report.
    case voucherReceipt: // Currently don't create an OTItem for voucher receipt
                         // in inbox. Used only for inbox report.

        SetNumberOfOrigin(0); // Not applicable.
        break;

    case acceptPending: // this item is a client-side acceptance of a pending
                        // transfer
    case rejectPending: // this item is a client-side rejection of a pending
                        // transfer
    case acceptCronReceipt:  // this item is a client-side acceptance of a cron
                             // receipt in his inbox.
    case acceptItemReceipt:  // this item is a client-side acceptance of an item
                             // receipt in his inbox.
    case disputeCronReceipt: // this item is a client dispute of a cron receipt
                             // in his inbox.
    case disputeItemReceipt: // this item is a client dispute of an item receipt
                             // in his inbox.

    case acceptFinalReceipt: // this item is a client-side acceptance of a final
                             // receipt in his inbox. (All related receipts must
                             // also be closed!)
    case acceptBasketReceipt: // this item is a client-side acceptance of a
                              // basket receipt in his inbox.
    case disputeFinalReceipt: // this item is a client-side rejection of a final
                              // receipt in his inbox. (All related receipts
                              // must also be closed!)
    case disputeBasketReceipt: // this item is a client-side rejection of a
                               // basket receipt in his inbox.

        otErr << __FUNCTION__ << ": In this case, you can't calculate the "
                                 "origin number, you must set it explicitly.\n";
        SetNumberOfOrigin(0); // Not applicable.
        // Comment this out later so people can't use it to crash the server:
        OT_FAIL_MSG("In this case, you can't calculate the origin number, you "
                    "must set it explicitly.");
        break;

    case marketReceipt: // server receipt dropped into inbox as result of market
                        // trading. Also used in inbox report.
    case paymentReceipt: // server receipt dropped into an inbox as result of
                         // payment occuring. Also used in inbox report.
    case finalReceipt:   // server receipt dropped into inbox / nymbox as result
                         // of cron item expiring or being canceled.
    case basketReceipt:  // server receipt dropped into inbox as result of a
                         // basket exchange.

        SetNumberOfOrigin(GetReferenceToNum()); // pending is in
                                                // reference to the
                                                // original
                                                // transfer.
        break;

    case depositCheque: // this item is a request to deposit a cheque.
    {
        Cheque theCheque;
        String strAttachment;
        GetAttachment(strAttachment);

        if (!theCheque.LoadContractFromString(strAttachment))
            otErr << __FUNCTION__ << ": ERROR loading cheque from string:\n"
                  << strAttachment << "\n";
        else
            SetNumberOfOrigin(theCheque.GetTransactionNum());
    } break;

    case atDepositCheque:     // this item is a server response to that request.
    case atAcceptPending:     // server reply to acceptPending.
    case atRejectPending:     // server reply to rejectPending.
    case atAcceptCronReceipt: // this item is a server reply to that acceptance.
    case atAcceptItemReceipt: // this item is a server reply to that acceptance.
    case atDisputeCronReceipt:   // Server reply to dispute message.
    case atDisputeItemReceipt:   // Server reply to dispute message.
    case atAcceptFinalReceipt:   // server reply
    case atAcceptBasketReceipt:  // server reply
    case atDisputeFinalReceipt:  // server reply
    case atDisputeBasketReceipt: // server reply
    {
        String strReference;
        GetReferenceString(strReference);

        // "In reference to" number is my original deposit trans#, which I use
        // here to load my
        // original depositCheque item, which I use to get the cheque, which
        // contains the number
        // of origin as its transaction number.
        //
        std::unique_ptr<Item> pOriginalItem(Item::CreateItemFromString(
            strReference, GetPurportedNotaryID(), GetReferenceToNum()));
        OT_ASSERT(nullptr != pOriginalItem);

        if (((m_Type == atDepositCheque) &&
             (Item::depositCheque != pOriginalItem->GetType())) ||
            ((m_Type == atAcceptPending) &&
             (Item::acceptPending != pOriginalItem->GetType())) ||
            ((m_Type == atRejectPending) &&
             (Item::rejectPending != pOriginalItem->GetType())) ||
            ((m_Type == atAcceptCronReceipt) &&
             (Item::acceptCronReceipt != pOriginalItem->GetType())) ||
            ((m_Type == atAcceptItemReceipt) &&
             (Item::acceptItemReceipt != pOriginalItem->GetType())) ||
            ((m_Type == atDisputeCronReceipt) &&
             (Item::disputeCronReceipt != pOriginalItem->GetType())) ||
            ((m_Type == atDisputeItemReceipt) &&
             (Item::disputeItemReceipt != pOriginalItem->GetType())) ||
            ((m_Type == atAcceptFinalReceipt) &&
             (Item::acceptFinalReceipt != pOriginalItem->GetType())) ||
            ((m_Type == atAcceptBasketReceipt) &&
             (Item::acceptBasketReceipt != pOriginalItem->GetType())) ||
            ((m_Type == atDisputeFinalReceipt) &&
             (Item::disputeFinalReceipt != pOriginalItem->GetType())) ||
            ((m_Type == atDisputeBasketReceipt) &&
             (Item::disputeBasketReceipt != pOriginalItem->GetType()))) {
            String strType;
            pOriginalItem->GetTypeString(strType);
            otErr << __FUNCTION__
                  << ": ERROR: Wrong item type as 'in reference to' string on "
                  << strType << " item.\n";
            SetNumberOfOrigin(0);
            return;
        }

        // Else:
        SetNumberOfOrigin(pOriginalItem->GetNumberOfOrigin());
    } break;

    // FEEs
    case serverfee: // this item is a fee from the transaction server (per
                    // contract)
    case atServerfee:
    case issuerfee: // this item is a fee from the issuer (per contract)
    case atIssuerfee:

    // INFO (BALANCE, HASH, etc) these are still all messages with replies.
    case balanceStatement: // this item is a statement of balance. (For asset
                           // account.)
    case atBalanceStatement:
    case transactionStatement: // this item is a transaction statement. (For Nym
                               // -- which numbers are assigned to him.)
    case atTransactionStatement:

    // TRANSFER
    case transfer:   // This item is an outgoing transfer, probably part of an
                     // outoing transaction.
    case atTransfer: // Server reply.

    // CASH WITHDRAWAL / DEPOSIT
    case withdrawal: // this item is a cash withdrawal (of chaumian blinded
                     // tokens)
    case atWithdrawal:
    case deposit: // this item is a cash deposit (of a purse containing blinded
                  // tokens.)
    case atDeposit:

    // CHEQUES AND VOUCHERS
    case withdrawVoucher: // this item is a request to purchase a voucher (a
                          // cashier's cheque)
    case atWithdrawVoucher:

    // PAYING DIVIDEND ON SHARES OF STOCK
    case payDividend:   // this item is a request to pay a dividend.
    case atPayDividend: // the server reply to that request.

    // TRADING ON MARKETS
    case marketOffer:   // this item is an offer to be put on a market.
    case atMarketOffer: // server reply or updated notification regarding a
                        // market offer.

    // PAYMENT PLANS
    case paymentPlan:   // this item is a new payment plan
    case atPaymentPlan: // server reply or updated notification regarding a
                        // payment plan.

    // SMART CONTRACTS
    case smartContract:   // this item is a new smart contract
    case atSmartContract: // server reply or updated notification regarding a
                          // smart contract.

    // CANCELLING: Market Offers and Payment Plans.
    case cancelCronItem:   // this item is intended to cancel a market offer or
                           // payment plan.
    case atCancelCronItem: // reply from the server regarding said cancellation.

    // EXCHANGE IN/OUT OF A BASKET CURRENCY
    case exchangeBasket:   // this item is an exchange in/out of a basket
                           // currency.
    case atExchangeBasket: // reply from the server regarding said exchange.

    default:
        SetNumberOfOrigin(GetTransactionNum());
        break;
    } // switch
}

void Item::GetAttachment(String& theStr) const
{
    m_ascAttachment.GetString(theStr);
}

void Item::SetAttachment(const String& theStr)
{
    m_ascAttachment.SetString(theStr);
}

void Item::SetNote(const String& theStr)
{
    if (theStr.Exists() && theStr.GetLength() > 2) {
        m_ascNote.SetString(theStr);
    }
    else {
        m_ascNote.Release();
    }
}

void Item::GetNote(String& theStr) const
{
    if (m_ascNote.GetLength() > 2) {
        m_ascNote.GetString(theStr);
    }
    else {
        theStr.Release();
    }
}

// Let's say you have created a transaction, and you are creating an item to put
// into it.
// Well in that case, you don't care to verify that the real IDs match the
// purported IDs, since
// you are creating this item yourself, not verifying it from someone else.
// Use this function to create the new Item before you add it to your new
// Transaction.
Item* Item::CreateItemFromTransaction(const OTTransaction& theOwner,
                                      Item::itemType theType,
                                      const Identifier* pDestinationAcctID)
{
    Item* pItem =
        new Item(theOwner.GetNymID(), theOwner, theType, pDestinationAcctID);

    if (pItem) {
        pItem->SetPurportedAccountID(theOwner.GetPurportedAccountID());
        pItem->SetPurportedNotaryID(theOwner.GetPurportedNotaryID());
        return pItem;
    }
    return nullptr;
}

// Sometimes I don't know user ID of the originator, or the account ID of the
// originator,
// until after I have loaded the item. It's simply impossible to set those
// values ahead
// of time, sometimes. In those cases, we set the values appropriately but then
// we need
// to verify that the user ID is actually the owner of the AccountID. TOdo that.
Item* Item::CreateItemFromString(const String& strItem,
                                 const Identifier& theNotaryID,
                                 int64_t lTransactionNumber)
{
    if (!strItem.Exists()) {
        otErr << "OTItem::CreateItemFromString: strItem is empty. (Expected an "
                 "item.)\n";
        return nullptr;
    }

    Item* pItem = new Item();

    // So when it loads its own server ID, we can compare to this one.
    pItem->SetRealNotaryID(theNotaryID);

    // This loads up the purported account ID and the user ID.
    if (pItem->LoadContractFromString(strItem)) {
        const Identifier& ACCOUNT_ID = pItem->GetPurportedAccountID();
        pItem->SetRealAccountID(ACCOUNT_ID); // I do this because it's all we've
                                             // got in this case. It's what's in
                                             // the
        // xml, so it must be right. If it's a lie, the signature will fail or
        // the
        // user will not show as the owner of that account. But remember, the
        // server
        // sent the message in the first place.

        pItem->SetTransactionNum(lTransactionNumber);

        if (pItem->VerifyContractID()) // this compares purported and real
                                       // account IDs, as well as server IDs.
        {
            return pItem;
        }
        else {
            delete pItem;
            pItem = nullptr;
        }
    }

    return nullptr;
}

void Item::InitItem()
{
    m_lAmount = 0; // Accounts default to ZERO.  They can only change that
                   // amount by receiving from another account.
    m_Type = Item::error_state;
    m_Status =
        Item::request; // (Unless an issuer account, which can create currency
    m_lNewOutboxTransNum = 0; // When the user puts a "1" in his outbox for a
                              // balance agreement (since he doesn't know what
                              // trans# the actual outbox item
    // will have if the transaction is successful, since the server hasn't
    // issued it yet) then the balance receipt will have 1 in
    // the user's portion for that outbox transaction, and the balance receipt
    // will also have, say, #34 (the actual number) here
    // in this variable, in the server's reply portion of that same receipt.

    m_lClosingTransactionNo = 0;

    m_strContractType = "TRANSACTION ITEM"; // CONTRACT, MESSAGE, TRANSACTION,
                                            // LEDGER, TRANSACTION ITEM
}

// this one is private (I hope to keep it that way.)
// probvably not actually. If I end up back here, it's because
// sometimes I dont' WANT to assign the stuff, but leave it blank
// because I'm about to load it.
Item::Item()
    : OTTransactionType()
    , m_lAmount(0)
    , m_Type(Item::error_state)
    , m_Status(Item::request)
    , m_lNewOutboxTransNum(0)
    , m_lClosingTransactionNo(0)
{
    InitItem();
}

// From owner we can get acct ID, server ID, and transaction Num
Item::Item(const Identifier& theNymID, const OTTransaction& theOwner)
    : OTTransactionType(theNymID, theOwner.GetRealAccountID(),
                        theOwner.GetRealNotaryID(),
                        theOwner.GetTransactionNum())
    , m_lAmount(0)
    , m_Type(Item::error_state)
    , m_Status(Item::request)
    , m_lNewOutboxTransNum(0)
    , m_lClosingTransactionNo(0)
{
    InitItem();
}

// From owner we can get acct ID, server ID, and transaction Num
Item::Item(const Identifier& theNymID, const Item& theOwner)
    : OTTransactionType(theNymID, theOwner.GetRealAccountID(),
                        theOwner.GetRealNotaryID(),
                        theOwner.GetTransactionNum())
    , m_lAmount(0)
    , m_Type(Item::error_state)
    , m_Status(Item::request)
    , m_lNewOutboxTransNum(0)
    , m_lClosingTransactionNo(0)
{
    InitItem();
}

Item::Item(const Identifier& theNymID, const OTTransaction& theOwner,
           Item::itemType theType, const Identifier* pDestinationAcctID)
    : OTTransactionType(theNymID, theOwner.GetRealAccountID(),
                        theOwner.GetRealNotaryID(),
                        theOwner.GetTransactionNum())
    , m_lAmount(0)
    , m_Type(Item::error_state)
    , m_Status(Item::request)
    , m_lNewOutboxTransNum(0)
    , m_lClosingTransactionNo(0)
{
    InitItem();

    m_Type = theType; // This has to be below the InitItem() call that appears
                      // just above

    // Most transactions items don't HAVE a "to" account, just a primary
    // account.
    // (If you deposit, or withdraw, you don't need a "to" account.)
    // But for the ones that do, you can pass the "to" account's ID in
    // as a pointer, and we'll set that too....
    if (nullptr != pDestinationAcctID) {
        m_AcctToID = *pDestinationAcctID;
    }
}

Item::~Item()
{
    Release_Item();
}

void Item::Release()
{
    Release_Item();

    ot_super::Release();
}

void Item::Release_Item()
{
    ReleaseItems();

    m_AcctToID.Release();
    m_lAmount = 0;
    m_lNewOutboxTransNum = 0;
    m_lClosingTransactionNo = 0;
}

void Item::ReleaseItems()
{

    while (!m_listItems.empty()) {
        Item* pItem = m_listItems.front();
        m_listItems.pop_front();
        delete pItem;
    }
}

Item::itemType Item::GetItemTypeFromString(const String& strType)
{
    Item::itemType theType = Item::error_state;

    if (strType.Compare("transfer"))
        theType = Item::transfer;
    else if (strType.Compare("atTransfer"))
        theType = Item::atTransfer;

    else if (strType.Compare("acceptTransaction"))
        theType = Item::acceptTransaction;
    else if (strType.Compare("atAcceptTransaction"))
        theType = Item::atAcceptTransaction;

    else if (strType.Compare("acceptMessage"))
        theType = Item::acceptMessage;
    else if (strType.Compare("atAcceptMessage"))
        theType = Item::atAcceptMessage;

    else if (strType.Compare("acceptNotice"))
        theType = Item::acceptNotice;
    else if (strType.Compare("atAcceptNotice"))
        theType = Item::atAcceptNotice;

    else if (strType.Compare("acceptPending"))
        theType = Item::acceptPending;
    else if (strType.Compare("atAcceptPending"))
        theType = Item::atAcceptPending;
    else if (strType.Compare("rejectPending"))
        theType = Item::rejectPending;
    else if (strType.Compare("atRejectPending"))
        theType = Item::atRejectPending;

    else if (strType.Compare("acceptCronReceipt"))
        theType = Item::acceptCronReceipt;
    else if (strType.Compare("atAcceptCronReceipt"))
        theType = Item::atAcceptCronReceipt;
    else if (strType.Compare("disputeCronReceipt"))
        theType = Item::disputeCronReceipt;
    else if (strType.Compare("atDisputeCronReceipt"))
        theType = Item::atDisputeCronReceipt;
    else if (strType.Compare("acceptItemReceipt"))
        theType = Item::acceptItemReceipt;
    else if (strType.Compare("atAcceptItemReceipt"))
        theType = Item::atAcceptItemReceipt;
    else if (strType.Compare("disputeItemReceipt"))
        theType = Item::disputeItemReceipt;
    else if (strType.Compare("atDisputeItemReceipt"))
        theType = Item::atDisputeItemReceipt;

    else if (strType.Compare("acceptFinalReceipt"))
        theType = Item::acceptFinalReceipt;
    else if (strType.Compare("atAcceptFinalReceipt"))
        theType = Item::atAcceptFinalReceipt;
    else if (strType.Compare("disputeFinalReceipt"))
        theType = Item::disputeFinalReceipt;
    else if (strType.Compare("atDisputeFinalReceipt"))
        theType = Item::atDisputeFinalReceipt;

    else if (strType.Compare("acceptBasketReceipt"))
        theType = Item::acceptBasketReceipt;
    else if (strType.Compare("atAcceptBasketReceipt"))
        theType = Item::atAcceptBasketReceipt;
    else if (strType.Compare("disputeBasketReceipt"))
        theType = Item::disputeBasketReceipt;
    else if (strType.Compare("atDisputeBasketReceipt"))
        theType = Item::atDisputeBasketReceipt;

    else if (strType.Compare("serverfee"))
        theType = Item::serverfee;
    else if (strType.Compare("atServerfee"))
        theType = Item::atServerfee;
    else if (strType.Compare("issuerfee"))
        theType = Item::issuerfee;
    else if (strType.Compare("atIssuerfee"))
        theType = Item::atIssuerfee;

    else if (strType.Compare("balanceStatement"))
        theType = Item::balanceStatement;
    else if (strType.Compare("atBalanceStatement"))
        theType = Item::atBalanceStatement;
    else if (strType.Compare("transactionStatement"))
        theType = Item::transactionStatement;
    else if (strType.Compare("atTransactionStatement"))
        theType = Item::atTransactionStatement;

    else if (strType.Compare("withdrawal"))
        theType = Item::withdrawal;
    else if (strType.Compare("atWithdrawal"))
        theType = Item::atWithdrawal;
    else if (strType.Compare("deposit"))
        theType = Item::deposit;
    else if (strType.Compare("atDeposit"))
        theType = Item::atDeposit;

    else if (strType.Compare("withdrawVoucher"))
        theType = Item::withdrawVoucher;
    else if (strType.Compare("atWithdrawVoucher"))
        theType = Item::atWithdrawVoucher;
    else if (strType.Compare("depositCheque"))
        theType = Item::depositCheque;
    else if (strType.Compare("atDepositCheque"))
        theType = Item::atDepositCheque;

    else if (strType.Compare("payDividend"))
        theType = Item::payDividend;
    else if (strType.Compare("atPayDividend"))
        theType = Item::atPayDividend;

    else if (strType.Compare("marketOffer"))
        theType = Item::marketOffer;
    else if (strType.Compare("atMarketOffer"))
        theType = Item::atMarketOffer;

    else if (strType.Compare("paymentPlan"))
        theType = Item::paymentPlan;
    else if (strType.Compare("atPaymentPlan"))
        theType = Item::atPaymentPlan;

    else if (strType.Compare("smartContract"))
        theType = Item::smartContract;
    else if (strType.Compare("atSmartContract"))
        theType = Item::atSmartContract;

    else if (strType.Compare("cancelCronItem"))
        theType = Item::cancelCronItem;
    else if (strType.Compare("atCancelCronItem"))
        theType = Item::atCancelCronItem;

    else if (strType.Compare("exchangeBasket"))
        theType = Item::exchangeBasket;
    else if (strType.Compare("atExchangeBasket"))
        theType = Item::atExchangeBasket;

    else if (strType.Compare("chequeReceipt"))
        theType = Item::chequeReceipt;
    else if (strType.Compare("voucherReceipt"))
        theType = Item::voucherReceipt;
    else if (strType.Compare("marketReceipt"))
        theType = Item::marketReceipt;
    else if (strType.Compare("paymentReceipt"))
        theType = Item::paymentReceipt;
    else if (strType.Compare("transferReceipt"))
        theType = Item::transferReceipt;

    else if (strType.Compare("finalReceipt"))
        theType = Item::finalReceipt;
    else if (strType.Compare("basketReceipt"))
        theType = Item::basketReceipt;

    else if (strType.Compare("replyNotice"))
        theType = Item::replyNotice;
    else if (strType.Compare("successNotice"))
        theType = Item::successNotice;
    else if (strType.Compare("notice"))
        theType = Item::notice;

    else
        theType = Item::error_state;

    return theType;
}

// return -1 if error, 0 if nothing, and 1 if the node was processed.
int32_t Item::ProcessXMLNode(irr::io::IrrXMLReader*& xml)
{
    if (!strcmp("item", xml->getNodeName())) {
        String strType, strStatus;

        strType = xml->getAttributeValue("type");
        strStatus = xml->getAttributeValue("status");

        // Type
        m_Type = GetItemTypeFromString(strType); // just above.

        // Status
        if (strStatus.Compare("request"))
            m_Status = Item::request;
        else if (strStatus.Compare("acknowledgement"))
            m_Status = Item::acknowledgement;
        else if (strStatus.Compare("rejection"))
            m_Status = Item::rejection;
        else
            m_Status = Item::error_status;

        String strAcctFromID, strAcctToID, strNotaryID, strNymID,
            strOutboxNewTransNum;

        strAcctFromID = xml->getAttributeValue("fromAccountID");
        strAcctToID = xml->getAttributeValue("toAccountID");
        strNotaryID = xml->getAttributeValue("notaryID");
        strNymID = xml->getAttributeValue("nymID");

        strOutboxNewTransNum = xml->getAttributeValue("outboxNewTransNum");

        if (strOutboxNewTransNum.Exists())
            m_lNewOutboxTransNum = strOutboxNewTransNum.ToLong();

        // an OTTransaction::blank may now contain 20 or 100 new numbers.
        // Therefore, the OTItem::acceptTransaction must contain the same list,
        // otherwise you haven't actually SIGNED for the list, have you!
        //
        if (Item::acceptTransaction == m_Type) {
            const String strTotalList =
                xml->getAttributeValue("totalListOfNumbers");
            m_Numlist.Release();

            if (strTotalList.Exists())
                m_Numlist.Add(strTotalList); // (Comma-separated list of numbers
                                             // now becomes std::set<int64_t>.)
        }

        Identifier ACCOUNT_ID(strAcctFromID), NOTARY_ID(strNotaryID),
            DESTINATION_ACCOUNT(strAcctToID), NYM_ID(strNymID);

        SetPurportedAccountID(ACCOUNT_ID); // OTTransactionType::m_AcctID  the
                                           // PURPORTED Account ID
        SetPurportedNotaryID(NOTARY_ID);   // OTTransactionType::m_AcctNotaryID
                                           // the PURPORTED Notary ID
        SetDestinationAcctID(DESTINATION_ACCOUNT);
        SetNymID(NYM_ID);

        if (!m_bLoadSecurely) {
            SetRealAccountID(ACCOUNT_ID);
            SetRealNotaryID(NOTARY_ID);
        }

        String strTemp;

        strTemp = xml->getAttributeValue("numberOfOrigin");
        if (strTemp.Exists()) SetNumberOfOrigin(strTemp.ToLong());

        strTemp = xml->getAttributeValue("transactionNum");
        if (strTemp.Exists()) SetTransactionNum(strTemp.ToLong());

        strTemp = xml->getAttributeValue("inReferenceTo");
        if (strTemp.Exists()) SetReferenceToNum(strTemp.ToLong());

        m_lAmount = String::StringToLong(xml->getAttributeValue("amount"));

        otLog3 << "Loaded transaction Item, transaction num "
               << GetTransactionNum()
               << ", In Reference To: " << GetReferenceToNum()
               << ", type: " << strType << ", status: " << strStatus << "\n";
        //                "fromAccountID:\n%s\n NymID:\n%s\n toAccountID:\n%s\n
        // notaryID:\n%s\n----------\n",
        //                strAcctFromID.Get(), strNymID.Get(),
        // strAcctToID.Get(), strNotaryID.Get()

        return 1;
    }
    else if (!strcmp("note", xml->getNodeName())) {
        if (!Contract::LoadEncodedTextField(xml, m_ascNote)) {
            otErr << "Error in OTItem::ProcessXMLNode: note field without "
                     "value.\n";
            return (-1); // error condition
        }

        return 1;
    }
    else if (!strcmp("inReferenceTo", xml->getNodeName())) {
        if (false == Contract::LoadEncodedTextField(xml, m_ascInReferenceTo)) {
            otErr << "Error in OTItem::ProcessXMLNode: inReferenceTo field "
                     "without value.\n";
            return (-1); // error condition
        }

        return 1;
    }
    else if (!strcmp("attachment", xml->getNodeName())) {
        if (!Contract::LoadEncodedTextField(xml, m_ascAttachment)) {
            otErr << "Error in OTItem::ProcessXMLNode: attachment field "
                     "without value.\n";
            return (-1); // error condition
        }

        return 1;
    }
    else if (!strcmp("transactionReport", xml->getNodeName())) {
        if ((Item::balanceStatement == m_Type) ||
            (Item::atBalanceStatement == m_Type)) {
            // Notice it initializes with the wrong transaction number, in this
            // case.
            // That's okay, because I'm setting it below with
            // pItem->SetTransactionNum...
            Item* pItem = new Item(GetNymID(), *this); // But I've also got
                                                       // ITEM types with
                                                       // the same names...
            // That way, it will translate the string and set the type
            // correctly.
            OT_ASSERT(nullptr != pItem); // That way I can use each item to
                                         // REPRESENT an inbox transaction

            // Type
            String strType;
            strType = xml->getAttributeValue(
                "type"); // it's reading a TRANSACTION type: chequeReceipt,
                         // voucherReceipt, marketReceipt, or paymentReceipt.
                         // But I also have the same names for item types.

            pItem->SetType(GetItemTypeFromString(
                strType)); // It's actually translating a transaction type to an
                           // item type. (Same names in the case of the 3
                           // receipts that matter for inbox reports for balance
                           // agreements.)

            pItem->SetAmount(
                String::StringToLong(xml->getAttributeValue("adjustment")));

            // Status
            pItem->SetStatus(Item::acknowledgement); // I don't need this, but
                                                     // I'd rather it not say
                                                     // error state. This way
                                                     // if it changes to
                                                     // error_state later, I
                                                     // know I had a problem.

            String strAccountID, strNotaryID, strNymID;

            strAccountID = xml->getAttributeValue("accountID");
            strNotaryID = xml->getAttributeValue("notaryID");
            strNymID = xml->getAttributeValue("nymID");

            Identifier ACCOUNT_ID(strAccountID), NOTARY_ID(strNotaryID),
                NYM_ID(strNymID);

            pItem->SetPurportedAccountID(
                ACCOUNT_ID); // OTTransactionType::m_AcctID  the PURPORTED
                             // Account ID
            pItem->SetPurportedNotaryID(
                NOTARY_ID); // OTTransactionType::m_AcctNotaryID the PURPORTED
                            // Notary ID
            pItem->SetNymID(NYM_ID);

            String strTemp;

            strTemp = xml->getAttributeValue("numberOfOrigin");
            if (strTemp.Exists()) pItem->SetNumberOfOrigin(strTemp.ToLong());

            strTemp = xml->getAttributeValue("transactionNum");
            if (strTemp.Exists()) pItem->SetTransactionNum(strTemp.ToLong());

            strTemp = xml->getAttributeValue("inReferenceTo");
            if (strTemp.Exists()) pItem->SetReferenceToNum(strTemp.ToLong());

            strTemp = xml->getAttributeValue(
                "closingTransactionNum"); // only used in the inbox report for
                                          // balance agreement.
            if (strTemp.Exists()) pItem->SetClosingNum(strTemp.ToLong());

            AddItem(*pItem); // <======= adding to list.

            otLog3 << "Loaded transactionReport Item, transaction num "
                   << pItem->GetTransactionNum()
                   << ", In Reference To: " << pItem->GetReferenceToNum()
                   << ", type: " << strType << "\n";
            //                         "fromAccountID:\n%s\n NymID:\n%s\n
            // toAccountID:\n%s\n notaryID:\n%s\n----------\n",
            //                         strAcctFromID.Get(), strNymID.Get(),
            // strAcctToID.Get(), strNotaryID.Get()
        }
        else {
            otErr << "Outbox hash in item wrong type (expected "
                     "balanceStatement or atBalanceStatement.\n";
        }

        return 1;
    }

    return 0;
}

// Used in balance agreement, part of the inbox report.
int64_t Item::GetClosingNum() const
{
    return m_lClosingTransactionNo;
}

void Item::SetClosingNum(int64_t lClosingNum)
{
    m_lClosingTransactionNo = lClosingNum;
}

void Item::GetStringFromType(Item::itemType theType, String& strType)
{
    switch (theType) {
    case Item::transfer:
        strType.Set("transfer");
        break;
    case Item::acceptTransaction:
        strType.Set("acceptTransaction");
        break;
    case Item::acceptMessage:
        strType.Set("acceptMessage");
        break;
    case Item::acceptNotice:
        strType.Set("acceptNotice");
        break;
    case Item::acceptPending:
        strType.Set("acceptPending");
        break;
    case Item::rejectPending:
        strType.Set("rejectPending");
        break;
    case Item::acceptCronReceipt:
        strType.Set("acceptCronReceipt");
        break;
    case Item::disputeCronReceipt:
        strType.Set("disputeCronReceipt");
        break;
    case Item::acceptItemReceipt:
        strType.Set("acceptItemReceipt");
        break;
    case Item::disputeItemReceipt:
        strType.Set("disputeItemReceipt");
        break;
    case Item::acceptFinalReceipt:
        strType.Set("acceptFinalReceipt");
        break;
    case Item::acceptBasketReceipt:
        strType.Set("acceptBasketReceipt");
        break;
    case Item::disputeFinalReceipt:
        strType.Set("disputeFinalReceipt");
        break;
    case Item::disputeBasketReceipt:
        strType.Set("disputeBasketReceipt");
        break;
    case Item::serverfee:
        strType.Set("serverfee");
        break;
    case Item::issuerfee:
        strType.Set("issuerfee");
        break;
    case Item::withdrawal:
        strType.Set("withdrawal");
        break;
    case Item::deposit:
        strType.Set("deposit");
        break;
    case Item::withdrawVoucher:
        strType.Set("withdrawVoucher");
        break;
    case Item::depositCheque:
        strType.Set("depositCheque");
        break;
    case Item::payDividend:
        strType.Set("payDividend");
        break;
    case Item::marketOffer:
        strType.Set("marketOffer");
        break;
    case Item::paymentPlan:
        strType.Set("paymentPlan");
        break;
    case Item::smartContract:
        strType.Set("smartContract");
        break;
    case Item::balanceStatement:
        strType.Set("balanceStatement");
        break;
    case Item::transactionStatement:
        strType.Set("transactionStatement");
        break;

    case Item::cancelCronItem:
        strType.Set("cancelCronItem");
        break;
    case Item::exchangeBasket:
        strType.Set("exchangeBasket");
        break;

    case Item::atCancelCronItem:
        strType.Set("atCancelCronItem");
        break;
    case Item::atExchangeBasket:
        strType.Set("atExchangeBasket");
        break;

    case Item::chequeReceipt: // used for inbox statements in balance
                              // agreement.
        strType.Set("chequeReceipt");
        break;
    case Item::voucherReceipt: // used for inbox statements in balance
                               // agreement.
        strType.Set("voucherReceipt");
        break;
    case Item::marketReceipt: // used as market receipt, and also for inbox
                              // statement containing market receipt will use
                              // this as well.
        strType.Set("marketReceipt");
        break;
    case Item::paymentReceipt: // used as payment receipt, also used in inbox
                               // statement as payment receipt.
        strType.Set("paymentReceipt");
        break;
    case Item::transferReceipt: // used in inbox statement as transfer
                                // receipt.
        strType.Set("transferReceipt");
        break;

    case Item::finalReceipt: // used for final receipt. Also used in inbox
                             // statement as final receipt. (For expiring or
                             // cancelled Cron Item.)
        strType.Set("finalReceipt");
        break;
    case Item::basketReceipt: // used in inbox statement as basket receipt.
                              // (For exchange.)
        strType.Set("basketReceipt");
        break;

    case Item::notice: // used in Nymbox statement as notification from
                       // server.
        strType.Set("notice");
        break;
    case Item::replyNotice: // some server replies (to your request) have a
                            // copy dropped into your nymbox, to make sure you
                            // received it.
        strType.Set("replyNotice");
        break;
    case Item::successNotice: // used in Nymbox statement as notification from
                              // server of successful sign-out of a trans#.
        strType.Set("successNotice");
        break;

    case Item::atTransfer:
        strType.Set("atTransfer");
        break;
    case Item::atAcceptTransaction:
        strType.Set("atAcceptTransaction");
        break;
    case Item::atAcceptMessage:
        strType.Set("atAcceptMessage");
        break;
    case Item::atAcceptNotice:
        strType.Set("atAcceptNotice");
        break;
    case Item::atAcceptPending:
        strType.Set("atAcceptPending");
        break;
    case Item::atRejectPending:
        strType.Set("atRejectPending");
        break;
    case Item::atAcceptCronReceipt:
        strType.Set("atAcceptCronReceipt");
        break;
    case Item::atDisputeCronReceipt:
        strType.Set("atDisputeCronReceipt");
        break;
    case Item::atAcceptItemReceipt:
        strType.Set("atAcceptItemReceipt");
        break;
    case Item::atDisputeItemReceipt:
        strType.Set("atDisputeItemReceipt");
        break;

    case Item::atAcceptFinalReceipt:
        strType.Set("atAcceptFinalReceipt");
        break;
    case Item::atAcceptBasketReceipt:
        strType.Set("atAcceptBasketReceipt");
        break;
    case Item::atDisputeFinalReceipt:
        strType.Set("atDisputeFinalReceipt");
        break;
    case Item::atDisputeBasketReceipt:
        strType.Set("atDisputeBasketReceipt");
        break;

    case Item::atServerfee:
        strType.Set("atServerfee");
        break;
    case Item::atIssuerfee:
        strType.Set("atIssuerfee");
        break;
    case Item::atWithdrawal:
        strType.Set("atWithdrawal");
        break;
    case Item::atDeposit:
        strType.Set("atDeposit");
        break;
    case Item::atWithdrawVoucher:
        strType.Set("atWithdrawVoucher");
        break;
    case Item::atDepositCheque:
        strType.Set("atDepositCheque");
        break;
    case Item::atPayDividend:
        strType.Set("atPayDividend");
        break;
    case Item::atMarketOffer:
        strType.Set("atMarketOffer");
        break;
    case Item::atPaymentPlan:
        strType.Set("atPaymentPlan");
        break;
    case Item::atSmartContract:
        strType.Set("atSmartContract");
        break;
    case Item::atBalanceStatement:
        strType.Set("atBalanceStatement");
        break;
    case Item::atTransactionStatement:
        strType.Set("atTransactionStatement");
        break;

    default:
        strType.Set("error-unknown");
        break;
    }
}

void Item::UpdateContents() // Before transmission or serialization, this is
                            // where the ledger saves its contents
{
    String strFromAcctID(GetPurportedAccountID()),
        strToAcctID(GetDestinationAcctID()),
        strNotaryID(GetPurportedNotaryID()), strType, strStatus,
        strNymID(GetNymID());

    GetStringFromType(m_Type, strType);

    switch (m_Status) {
    case Item::request:
        strStatus.Set("request");
        break;
    case Item::acknowledgement:
        strStatus.Set("acknowledgement");
        break;
    case Item::rejection:
        strStatus.Set("rejection");
        break;
    default:
        strStatus.Set("error-unknown");
        break;
    }

    // I release this because I'm about to repopulate it.
    m_xmlUnsigned.Release();

    Tag tag("item");

    tag.add_attribute("type", strType.Get());
    tag.add_attribute("status", strStatus.Get());
    tag.add_attribute("numberOfOrigin", // GetRaw so it doesn't calculate.
                      formatLong(GetRawNumberOfOrigin()));
    tag.add_attribute("transactionNum", formatLong(GetTransactionNum()));
    tag.add_attribute("notaryID", strNotaryID.Get());
    tag.add_attribute("nymID", strNymID.Get());
    tag.add_attribute("fromAccountID", strFromAcctID.Get());
    tag.add_attribute("toAccountID", strToAcctID.Get());
    tag.add_attribute("inReferenceTo", formatLong(GetReferenceToNum()));
    tag.add_attribute("amount", formatLong(m_lAmount));

    // Only used in server reply item:
    // atBalanceStatement. In cases
    // where the statement includes a
    // new outbox item, this variable is
    // used to transport the new
    // transaction number (generated on
    // server side for that new outbox
    // item) back to the client, so the
    // client knows the transaction
    // number to verify when he is
    // verifying the outbox against the
    // last signed receipt.
    if (m_lNewOutboxTransNum > 0)
        tag.add_attribute("outboxNewTransNum",
                          formatLong(m_lNewOutboxTransNum));
    else {
        // IF this item is "acceptTransaction" then this
        // will serialize the list of transaction numbers
        // being accepted. (They now support multiple
        // numbers.)
        if ((Item::acceptTransaction == m_Type) && (m_Numlist.Count() > 0)) {
            // m_Numlist.Count is always 0, except for
            // OTItem::acceptTransaction.
            String strListOfBlanks;

            if (true == m_Numlist.Output(strListOfBlanks))
                tag.add_attribute("totalListOfNumbers", strListOfBlanks.Get());
        }
    }

    if (m_ascNote.GetLength() > 2) {
        tag.add_tag("note", m_ascNote.Get());
    }

    if (m_ascInReferenceTo.GetLength() > 2) {
        tag.add_tag("inReferenceTo", m_ascInReferenceTo.Get());
    }

    if (m_ascAttachment.GetLength() > 2) {
        tag.add_tag("attachment", m_ascAttachment.Get());
    }

    if ((Item::balanceStatement == m_Type) ||
        (Item::atBalanceStatement == m_Type)) {

        // loop through the sub-items (only used for balance agreement.)
        //
        for (auto& it : m_listItems) {
            Item* pItem = it;
            OT_ASSERT(nullptr != pItem);

            String acctID(pItem->GetPurportedAccountID()),
                notaryID(pItem->GetPurportedNotaryID()),
                nymID(pItem->GetNymID());

            String receiptType;
            GetStringFromType(pItem->GetType(), receiptType);

            TagPtr tagReport(new Tag("transactionReport"));

            tagReport->add_attribute("type", receiptType.Exists()
                                                 ? receiptType.Get()
                                                 : "error_state");
            tagReport->add_attribute("adjustment",
                                     formatLong(pItem->GetAmount()));
            tagReport->add_attribute("accountID", acctID.Get());
            tagReport->add_attribute("nymID", nymID.Get());
            tagReport->add_attribute("notaryID", notaryID.Get());
            tagReport->add_attribute("numberOfOrigin",
                                     formatLong(pItem->GetRawNumberOfOrigin()));
            tagReport->add_attribute("transactionNum",
                                     formatLong(pItem->GetTransactionNum()));
            tagReport->add_attribute("closingTransactionNum",
                                     formatLong(pItem->GetClosingNum()));
            tagReport->add_attribute("inReferenceTo",
                                     formatLong(pItem->GetReferenceToNum()));

            tag.add_tag(tagReport);
        }
    }

    std::string str_result;
    tag.output(str_result);

    m_xmlUnsigned.Concatenate("%s", str_result.c_str());
}

} // namespace opentxs
