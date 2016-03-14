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

#ifndef OPENTXS_CORE_PROTO_HPP
#define OPENTXS_CORE_PROTO_HPP

#include <opentxs/core/Proto.hpp>

#include "OTData.hpp"
#include "crypto/OTASCIIArmor.hpp"
#include "util/Assert.hpp"

namespace opentxs
{
namespace proto
{
template<class T>
OTData ProtoAsData(const T& serialized)
{
    auto size = serialized.ByteSize();
    char* protoArray = new char [size];

    OT_ASSERT_MSG(nullptr != protoArray, "protoArray failed to dynamically allocate.");

    serialized.SerializeToArray(protoArray, size);
    OTData serializedData(protoArray, size);
    delete[] protoArray;
    return serializedData;
}

template<class T>
std::string ProtoAsString(const T& serialized)
{
    auto size = serialized.ByteSize();
    char* protoArray = new char [size];

    OT_ASSERT_MSG(nullptr != protoArray, "protoArray failed to dynamically allocate.");

    serialized.SerializeToArray(protoArray, size);
    std::string serializedData(protoArray, size);
    delete[] protoArray;
    return serializedData;
}

template<class T>
String ProtoAsArmored(const T& serialized, const String& header)
{
    auto data = ProtoAsData<T>(serialized);
    OTASCIIArmor armored(data);
    String output;
    armored.WriteArmoredString(output, header.Get());

    return output;
}

template<class T>
T DataToProto(const OTData& input)
{
    T serialized;
    serialized.ParseFromArray(input.GetPointer(), input.GetSize());

    return serialized;
}

template<class T>
T StringToProto(const String& input)
{
    OTASCIIArmor armored;
    String unconstInput(input);

    if (!armored.LoadFromString(unconstInput)) {
        std::cerr << __FUNCTION__ << "Failed to decode armored protobuf."
                  << std::endl;

        return T();
    } else {

        return DataToProto<T>(OTData(armored));
    }
}

} // namespace proto
} // namespace opentxs

#endif // OPENTXS_CORE_PROTO_HPP
