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

#ifndef OPENTXS_CORE_OTASSETCONTRACT_HPP
#define OPENTXS_CORE_OTASSETCONTRACT_HPP

#include <opentxs-proto/verify/VerifyContracts.hpp>

#include "opentxs/core/Contract.hpp"
#include "opentxs/core/Nym.hpp"
#include "opentxs/core/String.hpp"
#include "opentxs/core/contract/Signable.hpp"

namespace opentxs
{

class Account;
class AccountVisitor;
class Basket;
class Identifier;
class String;

class UnitDefinition : public Signable
{
private:
    typedef Signable ot_super;

    std::string primary_unit_name_;
    std::string short_name_;

    EXPORT Identifier GetID() const override;

protected:
    std::string primary_unit_symbol_;

    EXPORT static Identifier GetID(const proto::UnitDefinition& contract);

    EXPORT UnitDefinition(
        const ConstNym& nym,
        const proto::UnitDefinition serialized);
    EXPORT UnitDefinition(
        const ConstNym& nym,
        const std::string& shortname,
        const std::string& name,
        const std::string& symbol,
        const std::string& terms);

    EXPORT virtual proto::UnitDefinition IDVersion() const;
    EXPORT virtual proto::UnitDefinition SigVersion() const;

public:
    EXPORT static UnitDefinition* Create(
        const ConstNym& nym,
        const std::string& shortname,
        const std::string& name,
        const std::string& symbol,
        const std::string& terms,
        const std::string& tla,
        const uint32_t& power,
        const std::string& fraction);
    EXPORT static UnitDefinition* Create(
        const ConstNym& nym,
        const std::string& shortname,
        const std::string& name,
        const std::string& symbol,
        const std::string& terms,
        const uint64_t weight);
    EXPORT static UnitDefinition* Create(
        const ConstNym& nym,
        const std::string& shortname,
        const std::string& name,
        const std::string& symbol,
        const std::string& terms,
        const std::string& date);
    EXPORT static UnitDefinition* Factory(
        const ConstNym& nym,
        const proto::UnitDefinition& serialized);

    // Some instrument definitions keep a list of "user" accounts (the
    // complete set of
    // that type.)
    // This is called when the user creates a new asset account, in order to add
    // it to that list.
    // (Currently only operational for "shares", not "currencies", since it's
    // used exclusively
    // for the payment of dividends.)

    // adds the account to the list. (When account is created.)
    EXPORT bool AddAccountRecord(const Account& theAccount) const;

    // removes the account from the list. (When account is deleted.)
    EXPORT bool EraseAccountRecord(const Identifier& theAcctID) const;

    EXPORT bool VisitAccountRecords(AccountVisitor& visitor) const;

    EXPORT static std::string formatLongAmount(
        int64_t lValue, int32_t nFactor = 100, int32_t nPower = 2,
        const char* szCurrencySymbol = "",
        const char* szThousandSeparator = ",",
        const char* szDecimalPoint = ".");
    EXPORT static bool ParseFormatted(int64_t& lResult,
                                      const std::string& str_input,
                                      int32_t nFactor = 100, int32_t nPower = 2,
                                      const char* szThousandSeparator = ",",
                                      const char* szDecimalPoint = ".");
    EXPORT const std::string& GetCurrencyName() const
    {
        return primary_unit_name_;
    }
    EXPORT const std::string& GetCurrencySymbol() const
    {
        return primary_unit_symbol_;
    }

    EXPORT virtual bool DisplayStatistics(String& strContents) const;
    EXPORT const proto::UnitDefinition Contract() const;
    EXPORT bool FormatAmountLocale(int64_t amount, std::string& str_output,
                                   const std::string& str_thousand,
                                   const std::string& str_decimal) const;
    EXPORT bool FormatAmountWithoutSymbolLocale(
        int64_t amount, std::string& str_output,
        const std::string& str_thousand, const std::string& str_decimal) const;
    EXPORT bool StringToAmountLocale(int64_t& amount,
                                     const std::string& str_input,
                                     const std::string& str_thousand,
                                     const std::string& str_decimal) const;
    EXPORT OTData Serialize() const override;
    EXPORT bool Validate() const override;
    EXPORT std::string Name() const override { return short_name_; }
    EXPORT const proto::UnitDefinition PublicContract() const;

    EXPORT virtual int32_t DecimalPower() const { return 0; }
    EXPORT virtual std::string FractionalUnitName() const { return ""; }
    EXPORT virtual std::string TLA() const { return short_name_; }

    EXPORT virtual proto::UnitType Type() const = 0;

    EXPORT virtual ~UnitDefinition() = default;
};

} // namespace opentxs

#endif // OPENTXS_CORE_OTASSETCONTRACT_HPP
