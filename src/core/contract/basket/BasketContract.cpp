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

#include <opentxs/core/contract/basket/BasketContract.hpp>

#include <opentxs/core/contract/basket/Basket.hpp>
#include <opentxs/core/Nym.hpp>

namespace opentxs
{

Identifier BasketContract::CalculateBasketID(
    const proto::UnitDefinition& serialized)
{
    auto contract(serialized);
    contract.clear_id();
    contract.clear_nymid();
    contract.clear_publicnym();

    for (auto& item : *contract.mutable_basket()->mutable_item()) {
        item.clear_account();
    }

    return GetID(contract);
}

bool BasketContract::FinalizeTemplate(
    const ConstNym& nym,
    proto::UnitDefinition& serialized)
{
    std::unique_ptr<BasketContract> contract(new BasketContract(nym, serialized));

    if (!contract) { return false; }

    if (!contract->CalculateID()) { return false; }

    if (contract->nym_) {
        proto::UnitDefinition basket = contract->SigVersion();
        std::shared_ptr<proto::Signature> sig =
            std::make_shared<proto::Signature>();
        if (contract->nym_->Sign(basket, *sig)) {
            contract->signatures_.push_front(sig);
            serialized = contract->PublicContract();

            return proto::Check(serialized, 0, 0xFFFFFFFF, false);
        }
    }

    return false;
}

BasketContract::BasketContract(
    const ConstNym& nym,
    const proto::UnitDefinition serialized)
        : ot_super(nym, serialized)
{
    if (serialized.has_basket()) {

        if (serialized.basket().has_weight()) {
            weight_ = serialized.basket().weight();
        }

        for (auto& item : serialized.basket().item()) {
            subcontracts_.insert(
                {item.unit(), {item.account(), item.weight()}});
        }
    }
}

BasketContract::BasketContract(
    const ConstNym& nym,
    const std::string& shortname,
    const std::string& name,
    const std::string& symbol,
    const std::string& terms,
    const uint64_t weight)
        : ot_super(nym, shortname, name, symbol, terms)
        , weight_(weight)
{
}

proto::UnitDefinition BasketContract::IDVersion() const
{
    proto::UnitDefinition contract = ot_super::IDVersion();

    contract.set_type(proto::UNITTYPE_BASKET);

    auto basket = contract.mutable_basket();
    basket->set_version(1);
    basket->set_weight(weight_);

    // determinism here depends on the defined ordering of std::map
    for (auto& item : subcontracts_) {
        auto serialized = basket->add_item();
        serialized->set_version(1);
        serialized->set_unit(item.first);
        serialized->set_account(item.second.first);
        serialized->set_weight(item.second.second);
    }

    return contract;
}

proto::UnitDefinition BasketContract::BasketIDVersion() const
{
    auto contract = ot_super::SigVersion();

    for (auto& item : *(contract.mutable_basket()->mutable_item())) {
        item.clear_account();
    }

    return contract;
}

} // namespace opentxs
