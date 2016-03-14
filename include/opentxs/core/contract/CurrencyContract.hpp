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

#ifndef OPENTXS_CORE_CURRENCYCONTRACT_HPP
#define OPENTXS_CORE_CURRENCYCONTRACT_HPP

#include "opentxs/core/contract/UnitDefinition.hpp"

namespace opentxs
{

class Nym;

class CurrencyContract : public UnitDefinition
{
private:
    typedef UnitDefinition ot_super;
    friend ot_super;

    // ISO-4217. E.g., USD, AUG, PSE. Take as hint, not as contract.
    std::string tla_;
    // If value is 103, decimal power of 0 displays 103 (actual value.) Whereas
    // decimal power of 2 displays 1.03 and 4 displays .0103
    uint32_t power_;
    // "cents"
    std::string fractional_unit_name_;

    EXPORT CurrencyContract(
        const ConstNym& nym,
        const proto::UnitDefinition serialized);
    EXPORT CurrencyContract(
        const ConstNym& nym,
        const std::string& shortname,
        const std::string& name,
        const std::string& symbol,
        const std::string& terms,
        const std::string& tla,
        const uint32_t& power,
        const std::string& fraction);

    EXPORT proto::UnitDefinition IDVersion() const override;

public:
    EXPORT proto::UnitType Type() const override
    {
        return proto::UNITTYPE_CURRENCY;
    }

    EXPORT int32_t DecimalPower() const override
    {
        return power_;
    }
    EXPORT std::string FractionalUnitName() const override
    {
        return fractional_unit_name_;
    } // "cents"    (for example)
    EXPORT std::string TLA() const override
    {
        return tla_;
    } // "USD""     (for example)

    virtual ~CurrencyContract() = default;
};

} // namespace opentxs

#endif // OPENTXS_CORE_CURRENCYCONTRACT_HPP
