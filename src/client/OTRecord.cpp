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

#include <opentxs/client/OTRecord.hpp>
#include <opentxs/client/OTRecordList.hpp>
#include <opentxs/client/OpenTransactions.hpp>
#include <opentxs/client/OT_ME.hpp>
#include <opentxs/client/OTAPI.hpp>
#include <opentxs/client/OTAPI_Exec.hpp>

#include <opentxs/ext/OTPayment.hpp>

#include <opentxs/core/recurring/OTPaymentPlan.hpp>
#include <opentxs/core/Ledger.hpp>
#include <opentxs/core/Log.hpp>

#include <memory>
#include <algorithm>

namespace opentxs
{

bool OTRecord::FormatAmount(std::string& str_output) const
{
    if (m_str_amount.empty() ||
        m_str_instrument_definition_id.empty()) // Need these to do the
                                                // formatting.
    {
//      otOut << __FUNCTION__ << ": Unable to format amount. Type: " << m_str_type << " Amount: "
//            << m_str_amount << "  Asset: " << m_str_instrument_definition_id << "";
        return false;
    }
    str_output = OTAPI_Wrap::It()->FormatAmount(
        m_str_instrument_definition_id,
        OTAPI_Wrap::It()->StringToLong(m_str_amount));
    return (!str_output.empty());
}

bool OTRecord::FormatAmountWithoutSymbol(std::string& str_output)
{
    if (m_str_amount.empty() || m_str_instrument_definition_id.empty()) {
        return false;
    }

    str_output = OTAPI_Wrap::It()->FormatAmountWithoutSymbol(
        m_str_instrument_definition_id,
        OTAPI_Wrap::It()->StringToLong(m_str_amount));
    return (!str_output.empty());
}

bool OTRecord::FormatAmountLocale(std::string& str_output,
                                  const std::string& str_thousands,
                                  const std::string& str_decimal) const
{
    if (m_str_amount.empty() ||
        m_str_instrument_definition_id.empty()) // Need these to do the
                                                // formatting.
    {
//      otOut << __FUNCTION__ << ": Unable to format amount. Type: " << m_str_type << " Amount: "
//            << m_str_amount << "  Asset: " << m_str_instrument_definition_id << "";
        return false;
    }
    str_output = OTAPI_Wrap::It()->FormatAmountLocale(
        m_str_instrument_definition_id,
        OTAPI_Wrap::It()->StringToLong(m_str_amount), str_thousands,
        str_decimal);
    return (!str_output.empty());
}

bool OTRecord::FormatAmountWithoutSymbolLocale(std::string& str_output,
                                               const std::string& str_thousands,
                                               const std::string& str_decimal)
{
    if (m_str_amount.empty() || m_str_instrument_definition_id.empty()) {
        return false;
    }

    str_output = OTAPI_Wrap::It()->FormatAmountWithoutSymbolLocale(
        m_str_instrument_definition_id,
        OTAPI_Wrap::It()->StringToLong(m_str_amount), str_thousands,
        str_decimal);
    return (!str_output.empty());
}

bool OTRecord::FormatMailSubject(std::string& str_output) const
{
    str_output.clear();
    if (IsMail()) {
        if (!HasContents())
            str_output = "(empty subject)";
        else {
            std::string str_temp_contents = GetContents();

            if (str_temp_contents.compare(0, 8, "Subject:") == 0) {
                // Make the replacement.
                str_temp_contents.replace(0, 8, "");
            }
            // Trim it, since there is probably a space after "Subject:"
            // (Plus we want it trimmed anyway.)
            std::string str_contents = String::trim(str_temp_contents);
            // Cut the string at the first newline.
            //
            std::string::size_type pos_start = 0;
            std::string::size_type pos = str_contents.find("\r\n", pos_start);

            if (std::string::npos == pos) // Didn't find anything.
                pos = str_contents.find("\n", pos_start);
            if (std::string::npos != pos) // We found a newline.
                str_contents.erase(pos, std::string::npos);
            // Trim it again, just for good measure.
            str_output = String::trim(str_contents);
        }
    }
    return (!str_output.empty());
}
bool OTRecord::FormatShortMailDescription(std::string& str_output) const
{
    String strDescription;

    if (IsMail()) {
        if (!HasContents())
            strDescription.Set("(empty message)");
        else {
            std::string str_temp_contents = GetContents();
            std::string str_contents = String::trim(str_temp_contents);

            if (str_contents.compare(0, 8, "Subject:") == 0) {
                // Make the replacement.
                str_contents.replace(0, 8, "");
            }
            bool bTruncated = false;

            if (str_contents.size() > 30) {
                str_contents.erase(30, std::string::npos);
                bTruncated = true;
            }
            // Replace any newlines with spaces...
            //
            std::replace(str_contents.begin(), str_contents.end(), '\r', ' ');
            std::replace(str_contents.begin(), str_contents.end(), '\n', ' ');

            //          str_contents.erase(std::remove(str_contents.begin(),
            // str_contents.end(), '\n'), str_contents.end());
            //          str_contents.erase(std::remove(str_contents.begin(),
            // str_contents.end(), '\r'), str_contents.end());
            strDescription.Format("%s%s", String::trim(str_contents).c_str(),
                                  bTruncated ? "..." : "");
        }
    }
    str_output = strDescription.Get();
    return (!str_output.empty());
}
    
    
bool OTRecord::FormatDescription(std::string& str_output) const
{
    bool bIsSuccess  = false;
    const bool bHasSuccess = this->HasSuccess(bIsSuccess);
    // ----------------------------------------
    String strDescription, strStatus, strKind;

    if (IsRecord()) {
        if (IsExpired())
            strStatus = "(EXPIRED)"; // How to tell difference between
                                     // instrument that processed successfully
                                     // and THEN expired, versus one that
                                     // expired before processing successfully?
                                     // (See next comment.)
        else if (IsInvoice())
            strStatus = "(payment sent)"; // TODO: need an "invalid records" box
                                          // for expired and canceled. Otherwise
                                          // we may falsely assume "payment
                                          // sent" when actually it expired. (We
                                          // may also falsely assume payment
                                          // expired when actually it was sent.)
                                          // Solution is a new box.
        else if (IsNotice())
        {
            if (bHasSuccess)
            {
                if (bIsSuccess)
                    strStatus = "(activated)";
                else
                    strStatus = "(failed activating)";
            }
        }
        else
            strStatus = "";
//          strStatus = "(record)";
    }
    else if (IsPending()) {
        if (IsExpired())
            strStatus = "(EXPIRED)";
        else if (IsInvoice())
            strStatus = "(unpaid)";
        else if (!IsCash())
            strStatus = "(pending)";
    }
    // ----------------------------------------
    if (IsCanceled()) {
        strStatus = "(CANCELED)";

        if (IsOutgoing() || IsReceipt())
            strKind.Format("%s", "sent ");
    }
    else {
        if (IsOutgoing())
            strKind.Format(
                "%s", ((IsPending() && !IsCash()) ? "outgoing " : "sent "));
        else // Incoming.
            strKind.Format(
                "%s", IsPending() ? "incoming "
                                  : (IsReceipt() ? "" : "received "));
    }
    // ----------------------------------------
    String strTransNumForDisplay;

    if (!IsCash())
        strTransNumForDisplay.Format(" #%" PRId64, GetTransNumForDisplay());
    // ----------------------------------------
    if (IsRecord()) {
        if (IsTransfer())
            strDescription.Format("%s%s%s %s", strKind.Get(), "transfer",
                                  strTransNumForDisplay.Get(), strStatus.Get());
        else if (IsVoucher())
            strDescription.Format("%s%s%s %s", strKind.Get(), "payment",
                                  strTransNumForDisplay.Get(), strStatus.Get());
        else if (IsReceipt()) {
            std::string str_instrument_type;

            if (0 == GetInstrumentType().compare("transferReceipt"))
                str_instrument_type = "transfer";
            else if (0 == GetInstrumentType().compare("finalReceipt"))
                str_instrument_type = "final receipt (closed)";
            else if (0 == GetInstrumentType().compare("marketReceipt")) {
                const int64_t lAmount =
                    OTAPI_Wrap::It()->StringToLong(m_str_amount);

                // I *think* successful trades have a negative amount -- we'll
                // find out!
                //
                if (lAmount == 0)
                    str_instrument_type = "failed trade";
                else {
                    str_instrument_type = "market trade (receipt)";
                }
            }
            else if (0 == GetInstrumentType().compare("chequeReceipt")) {
                const int64_t lAmount =
                    OTAPI_Wrap::It()->StringToLong(m_str_amount);

                // I paid OUT when this chequeReceipt came through. It must be a
                // normal cheque that I wrote.
                if (lAmount <= 0) // Notice less than OR EQUAL TO 0 -- that's
                                  // because a canceled cheque has a 0 value.
                    str_instrument_type = "cheque";
                else // I GOT PAID when this chequeReceipt came through. It must
                     // be an invoice I wrote, that someone paid.
                {
                    if (IsCanceled())
                        str_instrument_type = "invoice";
                    else
                        str_instrument_type = "invoice (payment received)";
                }
            }
            else if (0 == GetInstrumentType().compare("voucherReceipt")) {
                str_instrument_type = "payment";
            }
            else if (0 == GetInstrumentType().compare("paymentReceipt")) {
                const int64_t lAmount =
                    OTAPI_Wrap::It()->StringToLong(m_str_amount);

                if (!IsCanceled() && (lAmount > 0))
                    strKind.Set("received ");

                str_instrument_type = "recurring payment";
            }

            strDescription.Format("%s%s%s %s", strKind.Get(),
                                  str_instrument_type.c_str(),
                                  strTransNumForDisplay.Get(), strStatus.Get());
        } // IsReceipt
        else
            strDescription.Format("%s%s%s %s", strKind.Get(),
                                  GetInstrumentType().c_str(),
                                  strTransNumForDisplay.Get(), strStatus.Get());
    } // IsRecord
    // ----------------------------------------
    else {
        if (IsTransfer())
            strDescription.Format("%s %s%s%s", strStatus.Get(), strKind.Get(),
                                  "transfer", strTransNumForDisplay.Get());
        else if (IsVoucher())
            strDescription.Format("%s %s%s%s", strStatus.Get(), strKind.Get(),
                                  "payment", strTransNumForDisplay.Get());

        else if (IsReceipt()) {
            std::string str_instrument_type;

            if (0 == GetInstrumentType().compare("transferReceipt")) {
                if (IsCanceled())
                    str_instrument_type = "transfer";
                else
                    str_instrument_type = "transfer (receipt)";
            }
            else if (0 == GetInstrumentType().compare("finalReceipt"))
                str_instrument_type = "final receipt";
            else if (0 == GetInstrumentType().compare("marketReceipt")) {
                const int64_t lAmount =
                    OTAPI_Wrap::It()->StringToLong(m_str_amount);

                // I *think* marketReceipts have negative value. We'll just test
                // for non-zero.
                if (lAmount == 0)
                    str_instrument_type = "failed trade";
                else
                    str_instrument_type = "market trade (receipt)";
            }
            else if (0 == GetInstrumentType().compare("chequeReceipt")) {
                const int64_t lAmount =
                    OTAPI_Wrap::It()->StringToLong(m_str_amount);

                // I paid OUT when this chequeReceipt came through. It must be a
                // normal cheque that I wrote.
                if (lAmount <= 0) // Notice less than OR EQUAL TO 0 -- that's
                                  // because a canceled cheque has a 0 value.
                {
                    if (IsCanceled())
                        str_instrument_type = "cheque";
                    else
                        str_instrument_type = "cheque (receipt)";
                }
                else // I GOT PAID when this chequeReceipt came through. It
                       // must be an invoice I wrote, that someone paid.
                {
                    if (IsCanceled())
                        str_instrument_type = "invoice";
                    else
                        str_instrument_type =
                            "sent invoice (receipt: payment received)";
                }
            }
            else if (0 == GetInstrumentType().compare("voucherReceipt")) {
                if (IsCanceled())
                    str_instrument_type = "payment";
                else
                    str_instrument_type = "payment (receipt)";
            }
            else if (0 == GetInstrumentType().compare("paymentReceipt")) {
                const int64_t lAmount =
                    OTAPI_Wrap::It()->StringToLong(m_str_amount);

                if (!IsCanceled() && (lAmount > 0))
                    strKind.Set("received ");

                str_instrument_type = "recurring payment (receipt)";
            }

            strDescription.Format("%s %s%s%s", strStatus.Get(), strKind.Get(),
                                  str_instrument_type.c_str(),
                                  strTransNumForDisplay.Get());
        }
        else
            strDescription.Format("%s %s%s%s", strStatus.Get(), strKind.Get(),
                                  GetInstrumentType().c_str(),
                                  strTransNumForDisplay.Get());
    } // Not Record.
    // ----------------------------------------
    str_output = strDescription.Get();
    return (!str_output.empty());
}
bool OTRecord::HasInitialPayment() const
{
    if (!IsPaymentPlan()) return false;

    OTPaymentPlan thePlan;
    const String strPlan(GetContents().c_str());

    if (thePlan.LoadContractFromString(strPlan) && thePlan.HasInitialPayment())
        return true;
    return false;
}

bool OTRecord::HasPaymentPlan() const
{
    if (!IsPaymentPlan()) return false;

    OTPaymentPlan thePlan;
    const String strPlan(GetContents().c_str());

    if (thePlan.LoadContractFromString(strPlan) && thePlan.HasPaymentPlan())
        return true;
    return false;
}

time64_t OTRecord::GetInitialPaymentDate() const
{
    if (!IsPaymentPlan()) return OT_TIME_ZERO;

    OTPaymentPlan thePlan;
    const String strPlan(GetContents().c_str());

    if (thePlan.LoadContractFromString(strPlan) && thePlan.HasInitialPayment())
        return thePlan.GetInitialPaymentDate();
    return OT_TIME_ZERO;
}

int64_t OTRecord::GetInitialPaymentAmount() const
{
    if (!IsPaymentPlan()) return 0;

    OTPaymentPlan thePlan;
    const String strPlan(GetContents().c_str());

    if (thePlan.LoadContractFromString(strPlan) && thePlan.HasInitialPayment())
        return thePlan.GetInitialPaymentAmount();
    return 0;
}

time64_t OTRecord::GetPaymentPlanStartDate() const
{
    if (!IsPaymentPlan()) return OT_TIME_ZERO;

    OTPaymentPlan thePlan;
    const String strPlan(GetContents().c_str());

    if (thePlan.LoadContractFromString(strPlan) && thePlan.HasPaymentPlan())
        return thePlan.GetPaymentPlanStartDate();
    return OT_TIME_ZERO;
}

time64_t OTRecord::GetTimeBetweenPayments() const
{
    if (!IsPaymentPlan()) return OT_TIME_ZERO;

    OTPaymentPlan thePlan;
    const String strPlan(GetContents().c_str());

    if (thePlan.LoadContractFromString(strPlan) && thePlan.HasPaymentPlan())
        return thePlan.GetTimeBetweenPayments();
    return OT_TIME_ZERO;
}

int64_t OTRecord::GetPaymentPlanAmount() const
{
    if (!IsPaymentPlan()) return 0;

    OTPaymentPlan thePlan;
    const String strPlan(GetContents().c_str());

    if (thePlan.LoadContractFromString(strPlan) && thePlan.HasPaymentPlan())
        return thePlan.GetPaymentPlanAmount();
    return 0;
}

int32_t OTRecord::GetMaximumNoPayments() const
{
    if (!IsPaymentPlan()) return 0;

    OTPaymentPlan thePlan;
    const String strPlan(GetContents().c_str());

    if (thePlan.LoadContractFromString(strPlan) && thePlan.HasPaymentPlan())
        return thePlan.GetMaximumNoPayments();
    return 0;
}
OTRecord::OTRecordType OTRecord::GetRecordType() const
{
    return m_RecordType;
}
// For completed records (not pending.)
//
bool OTRecord::CanDeleteRecord() const
{
    if (IsMail()) return true;

    if (!IsRecord()) return false;

    if (IsPending()) // This may be superfluous given the above 'if'
                     // statement.
        return false;

    return true;
}
// For incoming, pending (not-yet-accepted) instruments.
//
bool OTRecord::CanAcceptIncoming() const
{
    // Commented out because a transferReceipt is in the inbox, but it
    // represents an outgoing payment.
    //    if (IsOutgoing()) // If it's outgoing, then it's definitely not
    // an incoming thing you can accept.
    //        return false;

    if (IsRecord()) // Records must be archived or deleted, not accepted
                    // or discarded.
        return false;

    if (IsExpired()) return false;

    if (IsReceipt()) // It's NOT a record... If it's a receipt, then yes,
                     // we can accept it.
        return true;

    if (IsMail()) // Can't "accept" mail, can only delete it.
        return false;

    if (IsPending() && IsOutgoing()) // It's not a record, it's not
                                     // a receipt. If it's pending,
                                     // is it Outgoing pending? (Can
                                     // only accept INCOMING
                                     // pending, not outgoing.)
        return false;

    return true;
}
// For INcoming, pending (not-yet-accepted) instruments.
//
bool OTRecord::CanDiscardIncoming() const
{
    if (IsOutgoing()) return false;

    if (!IsPending()) return false;

    if (IsMail()) return false;

    if (IsRecord()) // This may be superfluous given the above 'if'
                    // pending.
        return false;

    if (IsReceipt()) // Receipts must be accepted, not discarded.
        return false;

    if (OTRecord::Transfer == GetRecordType()) // All incoming, pending
                                               // instruments EXCEPT
                                               // transfer can be
                                               // discarded.
        return false;

    return true;
}
bool OTRecord::CanDiscardOutgoingCash() const // For OUTgoing cash. (No way to
                                              // see if it's been accepted, so
                                              // this lets you erase the record
                                              // of sending it.)
{
    if (!IsOutgoing()) return false;

    if (!IsPending()) return false;

    if (!IsCash()) return false;

    if (!(GetBoxIndex() >= 0)) return false;

    return true;
}
// For OUTgoing, pending (not-yet-accepted) instruments.
//
bool OTRecord::CanCancelOutgoing() const
{
    if (!IsOutgoing()) return false;

    if (IsCanceled()) // It's already canceled!
        return false;

    if (!IsPending()) return false;

    if (IsMail()) return false;

    if (IsRecord()) // This may be superfluous given the above 'if'
                    // pending.
        return false;

    if (IsReceipt()) // Receipts can't be canceled. (Probably
                     // superfluous.)
        return false;

    if (OTRecord::Transfer == GetRecordType()) // All outgoing, pending
                                               // instruments EXCEPT
                                               // transfer can be
                                               // canceled.
        return false;

    return true;
}

bool OTRecord::DiscardOutgoingCash() const
{
    if (!CanDiscardOutgoingCash()) return false;
    return OTAPI_Wrap::Nym_RemoveOutpaymentsByIndex(m_str_nym_id,
                                                    GetBoxIndex());
}

// For completed records (not pending.)
//
bool OTRecord::DeleteRecord() const
{
    if (!CanDeleteRecord()) return false;
    if (!m_bIsSpecialMail &&
        (m_str_notary_id.empty() || m_str_nym_id.empty())) {
        otErr << __FUNCTION__ << ": Error: missing server id ("
              << m_str_notary_id << ") or nym id (" << m_str_nym_id << ")\n";
        return false;
    }
    std::string str_using_account;

    if ((OTRecord::Transfer == GetRecordType()) ||
        (OTRecord::Receipt == GetRecordType())) {
        if (m_str_account_id.empty()) {
            otErr << __FUNCTION__
                  << ": Error: missing account id for transfer or receipt.\n";
            return false;
        }

        str_using_account = m_str_account_id;
    }
    else
        str_using_account = m_str_nym_id; // For instruments.
    switch (GetRecordType()) {
    // Delete from in-mail or out-mail.
    //
    case OTRecord::Mail: {
        // If it's a Bitmessage or any other "non-OT" mail, then we can't
        // delete it here. We have to assume the client application is
        // smart enough to check for this and perform the deletion itself.
        // (Not all client apps will even support forms of mail other than
        // OT mail.)
        //
        if (!m_bIsSpecialMail) {
            if (m_bIsOutgoing) // outgoing mail
            {
                int32_t nCount = OTAPI_Wrap::GetNym_OutmailCount(m_str_nym_id);
                for (int32_t nIndex = 0; nIndex < nCount; ++nIndex) {
                    const std::string str_contents(
                        OTAPI_Wrap::GetNym_OutmailContentsByIndex(m_str_nym_id,
                                                                  nIndex));

                    if (str_contents == m_str_contents) // found it.
                    {
                        return OTAPI_Wrap::Nym_RemoveOutmailByIndex(
                            m_str_nym_id, nIndex);
                    }
                }
            }
            else // incoming mail
            {
                int32_t nCount = OTAPI_Wrap::GetNym_MailCount(m_str_nym_id);
                for (int32_t nIndex = 0; nIndex < nCount; ++nIndex) {
                    const std::string str_contents(
                        OTAPI_Wrap::GetNym_MailContentsByIndex(m_str_nym_id,
                                                               nIndex));

                    if (str_contents == m_str_contents) // found it.
                    {
                        return OTAPI_Wrap::Nym_RemoveMailByIndex(m_str_nym_id,
                                                                 nIndex);
                    }
                }
            }
        }
        else
            return true;

        return false;
    } break;
    case OTRecord::Transfer:   // Delete from asset account recordbox.
    case OTRecord::Receipt:    // Delete from asset account recordbox.
    case OTRecord::Instrument: // Delete from Nym's recordbox.
    case OTRecord::Notice: // Delete from Nym's recordbox.
        break;
    default:
        otErr << __FUNCTION__ << ": Unexpected type: " << GetInstrumentType()
              << "\n";
        return false;
    }
    // The below section handles both the Nym's recordbox AND the Asset Account
    // recordbox.
    //
    if (0 == m_lTransactionNum) {
        otErr << __FUNCTION__
              << ": Error: Transaction number is 0, in recordbox for "
                 "server id (" << m_str_notary_id << "), nym id ("
              << m_str_nym_id << "), acct id (" << str_using_account << ")\n";
        return false;
    }
    const Identifier theNotaryID(m_str_notary_id), theNymID(m_str_nym_id),
        theAcctID(str_using_account); // this last one sometimes contains NymID
                                      // (see above.)

    Ledger* pRecordbox =
        OTAPI_Wrap::OTAPI()->LoadRecordBox(theNotaryID, theNymID, theAcctID);
    std::unique_ptr<Ledger> theRecordBoxAngel(pRecordbox);
    if (nullptr == pRecordbox) {
        otErr << __FUNCTION__ << ": Failed loading record box for server ID ("
              << m_str_notary_id << ") nymID "
                                    "(" << m_str_nym_id << ") accountID ("
              << str_using_account << ")\n";
        return false;
    }
    // Find the receipt in the recordbox that correlates to this OTRecord.
    //
    int nIndex = pRecordbox->GetTransactionIndex(m_lTransactionNum);

    if ((-1) == nIndex) {
        otErr << __FUNCTION__ << ": Error: Unable to find transaction "
              << m_lTransactionNum << " in recordbox "
                                      "for server id (" << m_str_notary_id
              << "), nym id (" << m_str_nym_id << "), acct id ("
              << str_using_account << ")\n";
        return false;
    }
    // Accept it.
    //
    return OTAPI_Wrap::ClearRecord(
        m_str_notary_id, m_str_nym_id, str_using_account, nIndex,
        false); // clear all = false. We're only clearing one record.
}
bool OTRecord::AcceptIncomingTransfer() const
{
    return AcceptIncomingTransferOrReceipt();
} // For incoming, pending (not-yet-accepted) transfers.
bool OTRecord::AcceptIncomingReceipt() const
{
    return AcceptIncomingTransferOrReceipt();
} // For incoming, (not-yet-accepted) receipts.
bool OTRecord::AcceptIncomingTransferOrReceipt() const
{
    if (!CanAcceptIncoming()) return false;

    switch (GetRecordType()) {
    // Accept transfer or receipt from asset account inbox.
    //
    case OTRecord::Transfer:
    case OTRecord::Receipt: {
        if (m_str_notary_id.empty() || m_str_nym_id.empty() ||
            m_str_account_id.empty()) {
            otErr << __FUNCTION__ << ": Error: missing server id ("
                  << m_str_notary_id << ") or nym id (" << m_str_nym_id
                  << ") or "
                     "acct id (" << m_str_account_id << ")\n";
            return false;
        }
        if (0 == m_lTransactionNum) {
            otErr << __FUNCTION__
                  << ": Error: Transaction number is 0, in asset "
                     "account inbox for server id (" << m_str_notary_id
                  << "), nym id (" << m_str_nym_id << ")\n";
            return false;
        }
        const Identifier theNotaryID(m_str_notary_id), theNymID(m_str_nym_id),
            theAcctID(m_str_account_id);

        // Open the Nym's asset account inbox.
        Ledger* pInbox =
            OTAPI_Wrap::OTAPI()->LoadInbox(theNotaryID, theNymID, theAcctID);
        std::unique_ptr<Ledger> theInboxAngel(pInbox);
        if (nullptr == pInbox) {
            otErr << __FUNCTION__
                  << ": Error: Unable to load asset account inbox for "
                     "server id (" << m_str_notary_id << "), nym id ("
                  << m_str_nym_id << ")\n";
            return false;
        }
        // Find the transfer/receipt therein that correlates to this OTRecord.
        //
        int nIndex = pInbox->GetTransactionIndex(m_lTransactionNum);

        if ((-1) == nIndex) {
            otErr << __FUNCTION__ << ": Error: Unable to find transaction "
                  << m_lTransactionNum << " in payment inbox "
                                          "for server id (" << m_str_notary_id
                  << "), nym id (" << m_str_nym_id << "), acct id ("
                  << m_str_account_id << ")\n";
            return false;
        }
        // Accept it.
        //
        String strIndices;
        strIndices.Format("%d", nIndex);
        const std::string str_indices(strIndices.Get());

        OT_ME madeEasy;

        return madeEasy.accept_inbox_items(m_str_account_id, 0, str_indices);
    } break;
    default:
        otErr << __FUNCTION__ << ": Unexpected type: " << GetInstrumentType()
              << "\n";
        return false;
    }

    return true;
}
// For incoming, pending (not-yet-accepted) instruments.
//
bool OTRecord::AcceptIncomingInstrument(const std::string& str_into_acct) const
{
    if (!CanAcceptIncoming()) return false;

    switch (GetRecordType()) {
    // Accept from Nym's payments inbox.
    //
    case OTRecord::Instrument: {
        if (m_str_notary_id.empty() || m_str_nym_id.empty()) {
            otErr << __FUNCTION__ << ": Error: missing server id ("
                  << m_str_notary_id << ") or nym id (" << m_str_nym_id
                  << ")\n";
            return false;
        }
        if (0 == m_lTransactionNum) {
            otErr << __FUNCTION__
                  << ": Error: Transaction number is 0, in payment "
                     "inbox for server id (" << m_str_notary_id << "), nym id ("
                  << m_str_nym_id << ")\n";
            return false;
        }
        const Identifier theNotaryID(m_str_notary_id), theNymID(m_str_nym_id);

        // Open the Nym's payments inbox.
        Ledger* pInbox =
            OTAPI_Wrap::OTAPI()->LoadPaymentInbox(theNotaryID, theNymID);
        std::unique_ptr<Ledger> theInboxAngel(pInbox);
        if (nullptr == pInbox) {
            otErr << __FUNCTION__
                  << ": Error: Unable to load payment inbox for server "
                     "id (" << m_str_notary_id << "), nym id (" << m_str_nym_id
                  << ")\n";
            return false;
        }
        // Find the payment therein that correlates to this OTRecord.
        //
        int nIndex = pInbox->GetTransactionIndex(m_lTransactionNum);

        if ((-1) == nIndex) {
            otErr << __FUNCTION__ << ": Error: Unable to find transaction "
                  << m_lTransactionNum << " in "
                                          "payment inbox for server id ("
                  << m_str_notary_id << "), nym id (" << m_str_nym_id << ")\n";
            return false;
        }
        // Accept it.
        //
        String strIndices;
        strIndices.Format("%d", nIndex);
        const std::string str_indices(strIndices.Get());

        const char * szPaymentType = IsPaymentPlan() ? "PAYMENT PLAN" : "ANY";
        
        // NOTE: Someday if the command line tool ever starts using OTRecordList, then we will
        // actually remove the block below, and ALLOW smart contracts to be activated here. That's
        // because we can just allow the user to enter confirmSmartContract which ALREADY expects
        // that it needs to ask the user to provide various Nym and Account Ids during the confirmation
        // process AT THE COMMAND LINE. But right now, only GUIs use OTRecordList, and you don't want
        // the GUI to hang up while the application is suddenly asking you questions on a command
        // line terminal somewhere!
        if (IsContract())
        {
            otErr << __FUNCTION__ << ": It's a bug that this function was even called in the first place! "
            "The reason is because you CANNOT confirm a smart contract here. The confirmation process requires "
            "a whole wizard so the user can select various Nyms and Accounts. The GUI must perform this process, and "
            "thus would do that instead of ever calling this function. (So why are we here again...?)\n";
            return false;
        }
        
        OT_ME madeEasy;
        std::string str_server_response;
        if (!madeEasy.accept_from_paymentbox_overload(str_into_acct, str_indices,
                                             szPaymentType, &str_server_response)) {
            otErr << __FUNCTION__
                  << ": Error while trying to accept this instrument.\n";
            return false;
        }
        else
            backlink_.notifyOfSuccessfulNotarization(str_into_acct,
                                                     m_str_nym_id,
                                                     m_str_notary_id,
                                                     str_server_response,
                                                     m_lTransactionNum,
                                                     m_lTransNumForDisplay);
    } // case: instrument
    break;
    default:
        otErr << __FUNCTION__ << ": Unexpected type: " << GetInstrumentType()
              << "\n";
        return false;
    }

    return true;
}
// For incoming, pending (not-yet-accepted) instruments.
//
bool OTRecord::DiscardIncoming() const
{
    if (!CanDiscardIncoming()) return false;

    switch (GetRecordType()) {
    case OTRecord::Instrument: {
        if (m_str_notary_id.empty() || m_str_nym_id.empty()) {
            otErr << __FUNCTION__ << ": Error: missing server id ("
                  << m_str_notary_id << ") or nym id (" << m_str_nym_id
                  << ")\n";
            return false;
        }
        if (0 == m_lTransactionNum) {
            otErr << __FUNCTION__ << ": Error: Transaction number is 0, in "
                                     "payment inbox for server id ("
                  << m_str_notary_id << "), nym id (" << m_str_nym_id << ")\n";
            return false;
        }
        const Identifier theNotaryID(m_str_notary_id), theNymID(m_str_nym_id);

        // Open the Nym's payments inbox.
        Ledger* pInbox =
            OTAPI_Wrap::OTAPI()->LoadPaymentInbox(theNotaryID, theNymID);
        std::unique_ptr<Ledger> theInboxAngel(pInbox);
        if (nullptr == pInbox) {
            otErr << __FUNCTION__
                  << ": Error: Unable to load payment inbox for server id ("
                  << m_str_notary_id << "), nym id (" << m_str_nym_id << ")\n";
            return false;
        }
        // Find the payment therein that correlates to this OTRecord.
        //
        int nIndex = pInbox->GetTransactionIndex(m_lTransactionNum);

        if ((-1) == nIndex) {
            otErr << __FUNCTION__ << ": Error: Unable to find transaction "
                  << m_lTransactionNum << " in "
                                          "payment inbox for server id ("
                  << m_str_notary_id << "), nym id (" << m_str_nym_id << ")\n";
            return false;
        }
        // Accept it.
        //
        String strIndices;
        strIndices.Format("%d", nIndex);
        const std::string str_indices(strIndices.Get());

        OT_ME madeEasy;

        return madeEasy.discard_incoming_payments(m_str_notary_id, m_str_nym_id,
                                                  str_indices);

    } // case: instrument
    break;
    default:
        otErr << __FUNCTION__ << ": Unexpected type: " << GetInstrumentType()
              << "\n";
        return false;
    }

    return true;
}
bool OTRecord::IsTransfer() const
{
    return (OTRecord::Transfer == m_RecordType);
}
bool OTRecord::IsCash() const
{
    return m_bIsCash;
}
bool OTRecord::IsNotice() const
{
    return m_bIsNotice;
}
bool OTRecord::IsInvoice() const
{
    return m_bIsInvoice;
}
bool OTRecord::IsCheque() const
{
    return m_bIsCheque;
}
bool OTRecord::IsVoucher() const
{
    return m_bIsVoucher;
}
bool OTRecord::IsContract() const
{
    return m_bIsSmartContract;
}
bool OTRecord::IsPaymentPlan() const
{
    return m_bIsPaymentPlan;
}
    
void OTRecord::SetSuccess(const bool bIsSuccess)
{
    m_bHasSuccess = true;
    m_bIsSuccess  = bIsSuccess;
}
    
bool OTRecord::HasSuccess(bool & bIsSuccess) const
{
    if (m_bHasSuccess)
        bIsSuccess = m_bIsSuccess;
    
    return m_bHasSuccess;
}
    
    
// For outgoing, pending (not-yet-accepted) instruments.
//
bool OTRecord::CancelOutgoing(std::string str_via_acct) const // This can be blank if it's a cheque.
{
    if (!CanCancelOutgoing()) return false;

    switch (GetRecordType()) {
    case OTRecord::Instrument: {
        if (m_str_nym_id.empty()) {
            otErr << __FUNCTION__ << ": Error: missing nym id (" << m_str_nym_id
                  << ")\n";
            return false;
        }

        const Identifier theNymID(m_str_nym_id);
        std::string str_using_acct;

        if (IsCheque()) {
            str_using_acct = m_str_account_id;
        }
        else {
            str_using_acct = str_via_acct;
        }
        if (str_using_acct.empty()) {
            otErr << __FUNCTION__ << ": Error: Missing account ID (FAILURE)\n";
            return false;
        }
        if (0 == m_lTransactionNum) {
            if (IsCash()) {
                // Maybe it's cash...
                std::string strOutpayment(
                    OTAPI_Wrap::GetNym_OutpaymentsContentsByIndex(
                        m_str_nym_id, GetBoxIndex()));

                if (strOutpayment.empty()) {
                    int32_t lIndex = GetBoxIndex();
                    otErr << __FUNCTION__
                          << ": Error: Blank outpayment at index " << lIndex
                          << "\n";
                    return false;
                }
                String strPayment(strOutpayment);
                OTPayment thePayment(strPayment);

                if (!thePayment.IsValid() || !thePayment.SetTempValues()) {
                    int32_t lIndex = GetBoxIndex();
                    otErr << __FUNCTION__
                          << ": Error: Invalid outpayment at index " << lIndex
                          << "\n";
                    return false;
                }
                int64_t lTransNum = 0;
                thePayment.GetOpeningNum(lTransNum, theNymID);
                if (0 == lTransNum) // Found it.
                {
                    int32_t lIndex = GetBoxIndex();
                    String strIndices;
                    strIndices.Format("%d", lIndex);
                    const std::string str_indices(strIndices.Get());
                    OT_ME madeEasy;

                    return madeEasy.cancel_outgoing_payments(
                        m_str_nym_id, str_using_acct, str_indices);
                }
                else {
                    otErr << __FUNCTION__
                          << ": Error: Transaction number is non-zero ("
                          << lTransNum
                          << "), for cash outgoing payment for nym id ("
                          << m_str_nym_id << ")\n";
                    return false;
                }
            } // IsCash()
            else {
                otErr << __FUNCTION__ << ": Error: Transaction number is 0, "
                                         "for non-cash outgoing payment for "
                                         "nym id (" << m_str_nym_id << ")\n";
                return false;
            }
        }
        // Find the payment in the Nym's outpayments box that correlates to this
        // OTRecord.
        //
        int32_t nCount = OTAPI_Wrap::GetNym_OutpaymentsCount(m_str_nym_id);

        for (int32_t nIndex = 0; nIndex < nCount; ++nIndex) {
            std::string strOutpayment(
                OTAPI_Wrap::GetNym_OutpaymentsContentsByIndex(m_str_nym_id,
                                                              nIndex));

            if (strOutpayment.empty()) {
                otErr << __FUNCTION__ << ": Error: Blank outpayment at index "
                      << nIndex << "\n";
                return false;
            }
            String strPayment(strOutpayment);
            OTPayment thePayment(strPayment);

            if (!thePayment.IsValid() || !thePayment.SetTempValues()) {
                otErr << __FUNCTION__ << ": Error: Invalid outpayment at index "
                      << nIndex << "\n";
                return false;
            }
            int64_t lTransNum = 0;
            thePayment.GetOpeningNum(lTransNum, theNymID);
            if (lTransNum == m_lTransactionNum) // Found it.
            {
                String strIndices;
                strIndices.Format("%d", nIndex);
                const std::string str_indices(strIndices.Get());
                OT_ME madeEasy;

                return madeEasy.cancel_outgoing_payments(
                    m_str_nym_id, str_using_acct, str_indices);
            }
        } // for
    } break;
    default:
        otErr << __FUNCTION__ << ": Unexpected type: " << GetInstrumentType()
              << "\n";
        return false;
    }

    return true;
}
int64_t OTRecord::GetTransactionNum() const
{
    return m_lTransactionNum;
} // Trans Num of receipt in the box. (Unless outpayment, contains number for
  // instrument.)
void OTRecord::SetTransactionNum(int64_t lTransNum)
{
    m_lTransactionNum = lTransNum;
}
int64_t OTRecord::GetTransNumForDisplay() const
{
    if (m_lTransNumForDisplay > 0) return m_lTransNumForDisplay;

    return m_lTransactionNum;
}
void OTRecord::SetTransNumForDisplay(int64_t lTransNum)
{
    m_lTransNumForDisplay = lTransNum;
}
void OTRecord::SetExpired()
{
    m_bIsExpired = true;
}
void OTRecord::SetCanceled()
{
    m_bIsCanceled = true;
}
bool OTRecord::IsMail() const
{
    return OTRecord::Mail == GetRecordType();
}
bool OTRecord::IsPending() const
{
    return m_bIsPending;
}
bool OTRecord::IsOutgoing() const
{
    return m_bIsOutgoing;
}
bool OTRecord::IsRecord() const
{
    return m_bIsRecord;
}
bool OTRecord::IsReceipt() const
{
    return m_bIsReceipt;
}
bool OTRecord::HasContents() const
{
    return !m_str_contents.empty();
}
bool OTRecord::HasMemo() const
{
    return !m_str_memo.empty();
}
bool OTRecord::IsExpired() const
{
    return m_bIsExpired;
}
bool OTRecord::IsCanceled() const
{
    return m_bIsCanceled;
}
const std::string& OTRecord::GetNotaryID() const
{
    return m_str_notary_id;
}
const std::string& OTRecord::GetInstrumentDefinitionID() const
{
    return m_str_instrument_definition_id;
}
const std::string& OTRecord::GetCurrencyTLA() const
{
    return m_str_currency_tla;
}
const std::string& OTRecord::GetNymID() const
{
    return m_str_nym_id;
}
const std::string& OTRecord::GetAccountID() const
{
    return m_str_account_id;
}
const std::string& OTRecord::GetOtherNymID() const
{
    return m_str_other_nym_id;
}
const std::string& OTRecord::GetOtherAccountID() const
{
    return m_str_other_account_id;
}
const std::string& OTRecord::GetName() const
{
    return m_str_name;
}
const std::string& OTRecord::GetDate() const
{
    return m_str_date;
}
const std::string& OTRecord::GetAmount() const
{
    return m_str_amount;
}
const std::string& OTRecord::GetInstrumentType() const
{
    return m_str_type;
}
const std::string& OTRecord::GetMemo() const
{
    return m_str_memo;
}
const std::string& OTRecord::GetContents() const
{
    return m_str_contents;
}
bool OTRecord::IsSpecialMail() const
{
    return m_bIsSpecialMail;
}
int32_t OTRecord::GetMethodID() const
{
    return m_nMethodID;
}
const std::string& OTRecord::GetAddress() const
{
    return m_str_my_address;
}
const std::string& OTRecord::GetOtherAddress() const
{
    return m_str_other_address;
}
const std::string& OTRecord::GetMsgID() const
{
    return m_str_msg_id;
}
const std::string& OTRecord::GetMsgType() const
{
    return m_str_msg_type;
}
const std::string& OTRecord::GetMsgTypeDisplay() const
{
    return m_str_msg_type_display;
}
void OTRecord::SetSpecialMail(bool bIsSpecial)
{
    m_bIsSpecialMail = bIsSpecial;
}
void OTRecord::SetMethodID(int32_t nMethodID)
{
    m_nMethodID = nMethodID;
}
void OTRecord::SetAddress(const std::string& str_Address)
{
    m_str_my_address = str_Address;
}
void OTRecord::SetOtherAddress(const std::string& str_Address)
{
    m_str_other_address = str_Address;
}
void OTRecord::SetMsgID(const std::string& str_id)
{
    m_str_msg_id = str_id;
}
void OTRecord::SetMsgType(const std::string& str_type)
{
    m_str_msg_type = str_type;
}
void OTRecord::SetMsgTypeDisplay(const std::string& str_type)
{
    m_str_msg_type_display = str_type;
}
int32_t OTRecord::GetBoxIndex() const
{
    return m_nBoxIndex;
}
void OTRecord::SetBoxIndex(int32_t nBoxIndex)
{
    m_nBoxIndex = nBoxIndex;
}
void OTRecord::SetMemo(const std::string& str_memo)
{
    m_str_memo = str_memo;
}
void OTRecord::SetOtherNymID(const std::string& str_ID)
{
    m_str_other_nym_id = str_ID;
}
void OTRecord::SetOtherAccountID(const std::string& str_ID)
{
    m_str_other_account_id = str_ID;
}
void OTRecord::SetContents(const std::string& str_contents)
{
    m_str_contents = str_contents;

    if (!m_str_contents.empty() &&
        ( (OTRecord::Instrument == GetRecordType()) || (OTRecord::Notice == GetRecordType()) )
        )
    {
        String strPayment(m_str_contents);
        OTPayment thePayment(strPayment);

        if (thePayment.IsValid() && thePayment.SetTempValues()) {
            switch (thePayment.GetType()) {
            case OTPayment::PURSE:
                m_bIsCash = true;
                break;
            case OTPayment::CHEQUE:
                m_bIsCheque = true;
                break;
            case OTPayment::VOUCHER:
                m_bIsVoucher = true;
                break;
            case OTPayment::INVOICE:
                m_bIsInvoice = true;
                break;
            case OTPayment::PAYMENT_PLAN:
                m_bIsPaymentPlan = true;
                break;
            case OTPayment::SMART_CONTRACT:
                m_bIsSmartContract = true;
                break;
            case OTPayment::NOTICE:
                m_bIsNotice = true;
                break;

            default:
                break;
            }
        }
    }
}
time64_t OTRecord::GetValidFrom() const
{
    return m_ValidFrom;
}
time64_t OTRecord::GetValidTo() const
{
    return m_ValidTo;
}
void OTRecord::SetDateRange(time64_t tValidFrom, time64_t tValidTo)
{
    m_ValidFrom = tValidFrom;
    m_ValidTo = tValidTo;
    time64_t tCurrentTime = OTAPI_Wrap::GetTime();
    if ((tValidTo > OT_TIME_ZERO) && (tCurrentTime > tValidTo) && !IsMail() &&
        !IsRecord())
        SetExpired();
}
bool OTRecord::operator<(const OTRecord& rhs)
{
    return m_ValidFrom < rhs.m_ValidFrom;
}
OTRecord::OTRecord(OTRecordList & backlink,
                   const std::string& str_notary_id,
                   const std::string& str_instrument_definition_id,
                   const std::string& str_currency_tla,
                   const std::string& str_nym_id,
                   const std::string& str_account_id,
                   const std::string& str_name, const std::string& str_date,
                   const std::string& str_amount, const std::string& str_type,
                   bool bIsPending, bool bIsOutgoing, bool bIsRecord,
                   bool bIsReceipt, OTRecordType eRecordType)
    
    : backlink_(backlink)
    , m_nBoxIndex(-1)
    , m_ValidFrom(OT_TIME_ZERO)
    , m_ValidTo(OT_TIME_ZERO)
    , m_str_notary_id(str_notary_id)
    , m_str_instrument_definition_id(str_instrument_definition_id)
    , m_str_currency_tla(str_currency_tla)
    , m_str_nym_id(str_nym_id)
    , m_str_account_id(str_account_id)
    , m_str_name(str_name)
    , m_str_date(str_date)
    , m_str_amount(str_amount)
    , m_str_type(str_type)
    , m_bIsSpecialMail(false)
    , m_nMethodID(0)
    , m_lTransactionNum(0)
    , m_lTransNumForDisplay(0)
    , m_bIsPending(bIsPending)
    , m_bIsOutgoing(bIsOutgoing)
    , m_bIsRecord(bIsRecord)
    , m_bIsReceipt(bIsReceipt)
    , m_bIsPaymentPlan(false)
    , m_bIsSmartContract(false)
    , m_bIsVoucher(false)
    , m_bIsCheque(false)
    , m_bIsInvoice(false)
    , m_bIsCash(false)
    , m_bIsNotice(false)
    , m_bIsExpired(false)
    , m_bIsCanceled(false)
    , m_RecordType(eRecordType)
{
}

} // namespace opentxs
