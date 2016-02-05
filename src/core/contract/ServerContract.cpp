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

#include <opentxs/core/contract/ServerContract.hpp>

#include <opentxs/core/Log.hpp>
#include <opentxs/core/Proto.hpp>
#include <opentxs/core/String.hpp>
#include <opentxs/core/app/App.hpp>

namespace opentxs
{

ServerContract::ServerContract(
    const proto::ServerContract& serialized)
{
    id_ = serialized.id();
    signatures_.push_front(
        SerializedSignature(
            std::make_shared<proto::Signature>(serialized.signature())));
    version_ = serialized.version();
    conditions_ = serialized.terms();
    auto listen = serialized.address(0);
    listen_params_.push_front({listen.host(), std::stoi(listen.port())});

    std::unique_ptr<Nym> nym(new Nym(String(serialized.nymid())));

    if (nym) {
        if (!nym->LoadCredentials(true)) { // This nym is not already stored
            nym->LoadCredentialIndex(serialized.publicnym());
            nym->WriteCredentials();  // Save the public nym for quicker loading
            nym->SaveCredentialIDs(); // next time.
        }
        nym_.reset(nym.release());
    }

    transport_key_.Assign(
        serialized.transportkey().c_str(),
        serialized.transportkey().size());
}

ServerContract* ServerContract::Create(
    Nym* nym,  // takes ownership
    const String& url,
    const uint32_t port,
    const String& terms,
    const String& name)
{
    OT_ASSERT(nullptr != nym);

    ServerContract* contract = new ServerContract;

    contract->version_ = 1;
    contract->nym_.reset(nym);
    contract->listen_params_.push_front({url, port});
    contract->conditions_ = terms;
    // TODO:: find the right defined constant. 32 is the correct size
    // according to https://github.com/zeromq/czmq
    contract->transport_key_.Assign(
        zcert_public_key(contract->PrivateTransportKey()),
        32);

    if (!contract->CalculateID()) { return nullptr; }

    if (contract->nym_) {
        proto::ServerContract serialized = contract->SigVersion();
        if (contract->nym_->Sign(serialized)) {
            contract->signatures_.push_front(
                std::make_shared<proto::Signature>(serialized.signature()));
        }
    }

    contract->SetName(name);

    if (!contract->Validate()) { return nullptr; }
    contract->Save();

    return contract;
}

ServerContract* ServerContract::Factory(
    const proto::ServerContract& serialized)
{
    if (!proto::Check<proto::ServerContract>(serialized, 0, 0xFFFFFFFF)) {
        return nullptr;
    }

    ServerContract* contract = new ServerContract(serialized);

    if (nullptr == contract) { return nullptr; }

    if (!contract->Validate()) { return nullptr; }

    return contract;
}

Identifier ServerContract::GetID() const
{
    auto contract = IDVersion();
    Identifier id;
    id.CalculateDigest(
        proto::ProtoAsData<proto::ServerContract>(contract));
    return id;
}

bool ServerContract::ConnectInfo(String& strHostname, uint32_t& nPort) const
{
    if (0 < listen_params_.size()) {
        ListenParam info = listen_params_.front();
        strHostname = info.first;
        nPort = info.second;
        return true;
    }
    return false;
}

proto::ServerContract ServerContract::IDVersion() const
{
    proto::ServerContract contract;

    contract.set_version(version_);
    contract.clear_id(); // reinforcing that this field must be blank.
    contract.clear_signature(); // reinforcing that this field must be blank.
    contract.clear_publicnym(); // reinforcing that this field must be blank.

    if (nullptr != nym_) {
        String nymID;
        nym_->GetIdentifier(nymID);
        contract.set_nymid(nymID.Get());
    }

    String url;
    uint32_t port = 0;
    ConnectInfo(url, port);
    auto addr = contract.add_address();
    addr->set_version(1);
    addr->set_type(proto::ADDRESSTYPE_IPV4);
    addr->set_host(url.Get());
    addr->set_port(std::to_string(port));

    contract.set_terms(conditions_.Get());
    contract.set_transportkey(
        transport_key_.GetPointer(),
        transport_key_.GetSize());

    return contract;
}

proto::ServerContract ServerContract::SigVersion() const
{
    auto contract = IDVersion();
    contract.set_id(ID().Get());

    return contract;
}

const proto::ServerContract ServerContract::Contract() const
{
    auto contract = SigVersion();
    *(contract.mutable_signature()) = *(signatures_.front());

    return contract;
}

const proto::ServerContract ServerContract::PublicContract() const
{
    auto contract = Contract();

    if (nym_) {
        auto publicNym = nym_-> SerializeCredentialIndex(Nym::FULL_CREDS);
        *(contract.mutable_publicnym()) = publicNym;
    }

    return contract;
}

const Nym* ServerContract::PublicNym() const
{
    auto nym = nym_->SerializeCredentialIndex(Nym::FULL_CREDS);

    Nym* tempNym = new Nym(String(nym.nymid()));
    tempNym->LoadCredentialIndex(nym);

    return tempNym;
}

bool ServerContract::Statistics(String& strContents) const
{
    const String strID(id_);

    strContents.Concatenate(" Notary Provider: %s\n"
                            " NotaryID: %s\n"
                            "\n",
                            nym_->GetNymName().Get(), strID.Get());

    return true;
}

const unsigned char* ServerContract::PublicTransportKey() const
{
    return static_cast<const unsigned char*>(transport_key_.GetPointer());
}

zcert_t* ServerContract::PrivateTransportKey() const
{
    OT_ASSERT(nym_);

    return nym_->TransportKey();
}

bool ServerContract::Save() const
{
    if (!Validate()) { return false; }

    return App::Me().DB().Store(Contract());
}

OTData ServerContract::Serialize() const
{
    return proto::ProtoAsData<proto::ServerContract>(Contract());
}

bool ServerContract::Validate() const
{
    bool validNym = false;

    if (nym_) {
        validNym = nym_->VerifyPseudonym();
    }
    auto contract = Contract();
    bool validSyntax = proto::Check<proto::ServerContract>(contract, 0, 0xFFFFFFFF);
    bool validSig = false;

    if (nym_) {
        validSig = nym_->Verify(
            proto::ProtoAsData<proto::ServerContract>(SigVersion()),
            *(signatures_.front()));
    }

    return (validNym && validSyntax && validSig);
}

bool ServerContract::SetName(const String& name)
{
    if (nullptr != nym_) {
        nym_->SetNymName(name);

        return nym_->SavePseudonym();
    }

    return false;
}

} // namespace opentxs
