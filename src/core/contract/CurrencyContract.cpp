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
 *       -- Currency Currencies, Markets, Payment Plans.
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

#include <opentxs/core/Nym.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/String.hpp>
#include <opentxs/core/contract/CurrencyContract.hpp>

namespace opentxs
{

CurrencyContract::CurrencyContract(
    const ConstNym& nym,
    const proto::UnitDefinition serialized)
        : ot_super(nym, serialized)
        , tla_(serialized.currency().tla())
        , power_(serialized.currency().power())
        , fractional_unit_name_(serialized.currency().fraction())
{
}

CurrencyContract::CurrencyContract(
    const ConstNym& nym,
    const std::string& shortname,
    const std::string& name,
    const std::string& symbol,
    const std::string& terms,
    const std::string& tla,
    const uint32_t& power,
    const std::string& fraction)
        : ot_super(nym, shortname, name, symbol, terms)
{
    tla_ = tla;
    power_ = power;
    fractional_unit_name_ = fraction;
}

proto::UnitDefinition CurrencyContract::IDVersion() const
{
    proto::UnitDefinition contract = ot_super::IDVersion();

    contract.set_type(proto::UNITTYPE_CURRENCY);

    auto currency = contract.mutable_currency();
    currency->set_version(1);
    currency->set_tla(tla_);
    currency->set_power(power_);
    currency->set_fraction(fractional_unit_name_);

    return contract;
}

} // namespace opentxs
