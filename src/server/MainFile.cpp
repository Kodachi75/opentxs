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

#include <opentxs-proto/verify/VerifyCredentials.hpp>

#include <opentxs/server/MainFile.hpp>

#include <opentxs/core/app/App.hpp>
#include <opentxs/server/OTServer.hpp>
#include <opentxs/core/String.hpp>
#include <opentxs/core/crypto/OTCachedKey.hpp>
#include <opentxs/core/crypto/OTASCIIArmor.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/Identifier.hpp>
#include <opentxs/core/Contract.hpp>
#include <opentxs/core/contract/ServerContract.hpp>
#include "opentxs/core/contract/UnitDefinition.hpp"
#include <opentxs/core/crypto/OTPassword.hpp>
#include <opentxs/core/OTStorage.hpp>
#include <opentxs/core/util/OTFolders.hpp>
#include <opentxs/core/util/Tag.hpp>
#include <irrxml/irrXML.hpp>
#include <string>
#include <memory>

namespace opentxs
{

MainFile::MainFile(OTServer* server)
    : version_()
    , server_(server)
{
}

bool MainFile::SaveMainFileToString(String& strMainFile)
{
    Tag tag("notaryServer");

    // We're on version 2.0 since adding the master key.
    tag.add_attribute("version",
                      OTCachedKey::It()->IsGenerated() ? "2.0" : version_);
    tag.add_attribute("notaryID", server_->m_strNotaryID.Get());
    tag.add_attribute("serverNymID", server_->m_strServerNymID.Get());
    tag.add_attribute("transactionNum",
                      formatLong(server_->transactor_.transactionNumber()));

    if (OTCachedKey::It()->IsGenerated()) // If it exists, then serialize it.
    {
        OTASCIIArmor ascMasterContents;

        if (OTCachedKey::It()->SerializeTo(ascMasterContents)) {
            tag.add_tag("cachedKey", ascMasterContents.Get());
        }
        else
            Log::vError(
                "%s: Failed trying to write master key to notary file.\n",
                __FUNCTION__);
    }

    // Save the basket account information

    for (auto& it : server_->transactor_.idToBasketMap_) {
        String strBasketID = it.first.c_str();
        String strBasketAcctID = it.second.c_str();

        const Identifier BASKET_ACCOUNT_ID(strBasketAcctID);
        Identifier BASKET_CONTRACT_ID;

        bool bContractID =
            server_->transactor_.lookupBasketContractIDByAccountID(
                BASKET_ACCOUNT_ID, BASKET_CONTRACT_ID);

        if (!bContractID) {
            Log::vError("%s: Error: Missing Contract ID for basket ID %s\n",
                        __FUNCTION__, strBasketID.Get());
            break;
        }

        String strBasketContractID(BASKET_CONTRACT_ID);

        TagPtr pTag(new Tag("basketInfo"));

        pTag->add_attribute("basketID", strBasketID.Get());
        pTag->add_attribute("basketAcctID", strBasketAcctID.Get());
        pTag->add_attribute("basketContractID", strBasketContractID.Get());

        tag.add_tag(pTag);
    }

    server_->transactor_.voucherAccounts_.Serialize(tag);

    std::string str_result;
    tag.output(str_result);

    strMainFile.Concatenate("%s", str_result.c_str());

    return true;
}

// Setup the default location for the Sever Main File...
// maybe this should be set differently...
// should be set in the servers configuration.
//
bool MainFile::SaveMainFile()
{
    // Get the loaded (or new) version of the Server's Main File.
    //
    String strMainFile;

    if (!SaveMainFileToString(strMainFile)) {
        Log::vError(
            "%s: Error saving to string. (Giving up on save attempt.)\n",
            __FUNCTION__);
        return false;
    }
    // Try to save the notary server's main datafile to local storage...
    //
    String strFinal;
    OTASCIIArmor ascTemp(strMainFile);

    if (false ==
        ascTemp.WriteArmoredString(strFinal, "NOTARY")) // todo hardcoding.
    {

        Log::vError("%s: Error saving notary (failed writing armored string)\n",
                    __FUNCTION__);
        return false;
    }
    // Save the Main File to the Harddrive... (or DB, if other storage module is
    // being used).
    //
    const bool bSaved = OTDB::StorePlainString(
        strFinal.Get(), ".", server_->m_strWalletFilename.Get());

    if (!bSaved) {
        Log::vError("%s: Error saving main file: %s\n", __FUNCTION__,
                    server_->m_strWalletFilename.Get());
    }
    return bSaved;
}

bool MainFile::CreateMainFile(const std::string& strContract,
                              const std::string& strNotaryID,
                              const std::string& strCert,
                              const std::string& strNymID,
                              const std::string& strCachedKey)
{
    if (!OTDB::StorePlainString(strContract, "contracts", strNotaryID)) {
        Log::Error("Failed trying to store the server contract.\n");
        return false;
    }

    if (!strCert.empty() &&
        !OTDB::StorePlainString(strCert, "certs", strNymID)) {
        Log::Error(
            "Failed trying to store the server Nym's public/private cert.\n");
        return false;
    }

    const char* szBlankFile = // todo hardcoding.
        "<notaryServer version=\"2.0\"\n"
        " notaryID=\"%s\"\n"
        " serverNymID=\"%s\"\n"
        " transactionNum=\"%ld\" >\n"
        "\n"
        "<cachedKey>\n"
        "%s</cachedKey>\n"
        "\n"
        "<accountList type=\"voucher\" count=\"0\" >\n"
        "\n"
        "</accountList>\n"
        "\n"
        "</notaryServer>\n\n";

    int64_t lTransNum = 5; // a starting point, for the new server.

    String strNotaryFile;
    strNotaryFile.Format(szBlankFile, strNotaryID.c_str(), strNymID.c_str(),
                         lTransNum, strCachedKey.c_str());

    std::string str_Notary(strNotaryFile.Get());

    if (!OTDB::StorePlainString(str_Notary, ".",
                                "notaryServer.xml")) // todo hardcoding.
    {
        Log::Error("Failed trying to store the new notaryServer.xml file.\n");
        return false;
    }
    OTASCIIArmor ascCachedKey;
    ascCachedKey.Set(strCachedKey.c_str());
    OTCachedKey::It()->SetCachedKey(ascCachedKey);

    if (!OTCachedKey::It()->HasHashCheck()) {
        OTPassword tempPassword;
        tempPassword.zeroMemory();
        std::shared_ptr<OTCachedKey> sharedPtr(OTCachedKey::It());
        sharedPtr->GetMasterPassword(
            sharedPtr, tempPassword,
            "We do not have a check hash yet for this password, "
            "please enter your password",
            true);
        if (!SaveMainFile()) {
            OT_FAIL;
        }
    }
    // At this point, the contract is saved, the cert is saved, and the
    // notaryServer.xml file
    // is saved. All we have left is the Nymfile, which we'll create.

    const String strServerNymID(strNymID.c_str());

    server_->m_nymServer.SetIdentifier(strServerNymID);

    if (!server_->m_nymServer.LoadCredentials(true)) {
        Log::vOutput(0, "%s: Error loading server credentials, or "
                        "certificate and private key.\n",
                     __FUNCTION__);
    }
    else if (!server_->m_nymServer.VerifyPseudonym()) {
        Log::vOutput(0, "%s: Error verifying server nym. Are you sure you "
                        "have the right ID?\n",
                     __FUNCTION__);
    }
    else if (!server_->m_nymServer.SaveSignedNymfile(server_->m_nymServer)) {
        Log::vOutput(0, "%s: Error saving new nymfile for server nym.\n",
                     __FUNCTION__);
    }
    else {
        Log::vOutput(0, "%s: OKAY, we have apparently created the new "
                        "server.\n"
                        "Let's try to load up your new server contract...\n",
                     __FUNCTION__);
        return true;
    }

    return false;
}

bool MainFile::LoadMainFile(bool bReadOnly)
{
    if (!OTDB::Exists(".", server_->m_strWalletFilename.Get())) {
        Log::vError("%s: Error finding file: %s\n", __FUNCTION__,
                    server_->m_strWalletFilename.Get());
        return false;
    }
    String strFileContents(OTDB::QueryPlainString(
        ".",
        server_->m_strWalletFilename.Get())); // <=== LOADING FROM DATA STORE.

    if (!strFileContents.Exists()) {
        Log::vError("%s: Unable to read main file: %s\n", __FUNCTION__,
                    server_->m_strWalletFilename.Get());
        return false;
    }

    bool bNeedToSaveAgain = false;

    bool bFailure = false;

    {
        OTStringXML xmlFileContents(strFileContents);

        if (false ==
            xmlFileContents.DecodeIfArmored()) // bEscapedIsAllowed=true by
                                               // default.
        {
            Log::vError("%s: Notary server file apparently was encoded and "
                        "then failed decoding. Filename: %s \n"
                        "Contents: \n%s\n",
                        __FUNCTION__, server_->m_strWalletFilename.Get(),
                        strFileContents.Get());
            return false;
        }
        irr::io::IrrXMLReader* xml =
            irr::io::createIrrXMLReader(xmlFileContents);
        std::unique_ptr<irr::io::IrrXMLReader> theXMLGuardian(xml);
        while (xml && xml->read()) {
            // strings for storing the data that we want to read out of the file

            String AssetName;
            String InstrumentDefinitionID;

            const String strNodeName(xml->getNodeName());

            switch (xml->getNodeType()) {
            case irr::io::EXN_TEXT:
                // in this xml file, the only text which occurs is the
                // messageText
                // messageText = xml->getNodeData();
                break;
            case irr::io::EXN_ELEMENT: {
                if (strNodeName.Compare("notaryServer")) {
                    version_ = xml->getAttributeValue("version");
                    server_->m_strNotaryID = xml->getAttributeValue("notaryID");
                    server_->m_strServerNymID =
                        xml->getAttributeValue("serverNymID");

                    String strTransactionNumber; // The server issues
                                                 // transaction numbers and
                                                 // stores the counter here
                                                 // for the latest one.
                    strTransactionNumber =
                        xml->getAttributeValue("transactionNum");
                    server_->transactor_.transactionNumber(
                        strTransactionNumber.ToLong());

                    Log::vOutput(
                        0,
                        "\nLoading Open Transactions server. File version: %s\n"
                        " Last Issued Transaction Number: %" PRId64
                        "\n Notary ID:     "
                        " %s\n Server Nym ID: %s\n",
                        version_.c_str(),
                        server_->transactor_.transactionNumber(),
                        server_->m_strNotaryID.Get(),
                        server_->m_strServerNymID.Get());

                }
                // todo in the future just remove masterkey. I'm leaving it for
                // now so people's
                // data files can get converted over. After a while just remove
                // it.
                //
                else if (strNodeName.Compare("masterKey") ||
                         strNodeName.Compare("cachedKey")) {
                    OTASCIIArmor ascCachedKey;

                    if (Contract::LoadEncodedTextField(xml, ascCachedKey)) {
                        // We successfully loaded the masterKey from file, so
                        // let's SET it
                        // as the master key globally...
                        //
                        OTCachedKey::It()->SetCachedKey(ascCachedKey);

                        if (!OTCachedKey::It()->HasHashCheck()) {
                            OTPassword tempPassword;
                            tempPassword.zeroMemory();
                            std::shared_ptr<OTCachedKey> sharedPtr(
                                OTCachedKey::It());
                            bNeedToSaveAgain = sharedPtr->GetMasterPassword(
                                sharedPtr, tempPassword,
                                "We do not have a check hash yet for this "
                                "password, "
                                "please enter your password",
                                true);
                        }
                    }

                    Log::vOutput(0, "\nLoading cachedKey:\n%s\n",
                                 ascCachedKey.Get());
                    //
                    // It's only here, AFTER the master key has been loaded,
                    // that we can
                    // go ahead and load the server user, the server contract,
                    // cron, etc.
                    // (It wasn't that way in version 1, before we had master
                    // keys.)
                    //
                    // This is, for example, 2.0
                    if (version_ != "1.0") {
                        if (!LoadServerUserAndContract()) {
                            Log::vError("%s: Failed calling "
                                        "LoadServerUserAndContract.\n",
                                        __FUNCTION__);
                            bFailure = true;
                        }
                    }
                }
                else if (strNodeName.Compare("accountList")) // the voucher
                                                               // reserve
                                                               // account IDs.
                {
                    const String strAcctType = xml->getAttributeValue("type");
                    const String strAcctCount = xml->getAttributeValue("count");

                    if ((-1) ==
                        server_->transactor_.voucherAccounts_.ReadFromXMLNode(
                            xml, strAcctType, strAcctCount))
                        Log::vError("%s: Error loading voucher accountList.\n",
                                    __FUNCTION__);
                }
                else if (strNodeName.Compare("basketInfo")) {
                    String strBasketID = xml->getAttributeValue("basketID");
                    String strBasketAcctID =
                        xml->getAttributeValue("basketAcctID");
                    String strBasketContractID =
                        xml->getAttributeValue("basketContractID");

                    const Identifier BASKET_ID(strBasketID),
                        BASKET_ACCT_ID(strBasketAcctID),
                        BASKET_CONTRACT_ID(strBasketContractID);

                    if (server_->transactor_.addBasketAccountID(
                            BASKET_ID, BASKET_ACCT_ID, BASKET_CONTRACT_ID))
                        Log::vOutput(0, "Loading basket currency info...\n "
                                        "Basket ID: %s\n Basket Acct ID: "
                                        "%s\n Basket Contract ID: %s\n",
                                     strBasketID.Get(), strBasketAcctID.Get(),
                                     strBasketContractID.Get());
                    else
                        Log::vError("Error adding basket currency info...\n "
                                    "Basket ID: %s\n Basket Acct ID: %s\n",
                                    strBasketID.Get(), strBasketAcctID.Get());
                }

                else {
                    // unknown element type
                    Log::vError("%s: Unknown element type: %s\n", __FUNCTION__,
                                xml->getNodeName());
                }
            } break;
            default:
                break;
            }
        }
    }
    if (!bReadOnly) {
        {
            if (bNeedToSaveAgain)
                SaveMainFile();
        }
    }
    return !bFailure;
}

bool MainFile::LoadServerUserAndContract()
{
    const char* szFunc = "MainFile::LoadServerUserAndContract";
    bool bSuccess = false;
    OT_ASSERT(!version_.empty());
    OT_ASSERT(server_->m_strNotaryID.Exists());
    OT_ASSERT(server_->m_strServerNymID.Exists());

    server_->m_nymServer.SetIdentifier(server_->m_strServerNymID);

    if (!server_->m_nymServer.LoadCredentials(true)) {
        Log::vOutput(0, "%s: Error loading server certificate and keys.\n",
                     szFunc);
    }
    else if (!server_->m_nymServer.VerifyPseudonym()) {
        Log::vOutput(0, "%s: Error verifying server nym.\n", szFunc);
    }
    else {
        // This file will be saved during the course of operation
        // Just making sure it is loaded up first.
        //
        bool bLoadedSignedNymfile =
            server_->m_nymServer.LoadSignedNymfile(server_->m_nymServer);
        OT_ASSERT_MSG(bLoadedSignedNymfile,
                      "ASSERT: MainFile::LoadServerUserAndContract: "
                      "m_nymServer.LoadSignedNymfile(m_nymServer)\n");
        //      m_nymServer.SaveSignedNymfile(m_nymServer); // Uncomment this if
        // you want to create the file. NORMALLY LEAVE IT OUT!!!! DANGEROUS!!!

        Log::vOutput(
            0,
            "%s: Loaded server certificate and keys.\nNext, loading Cron...\n",
            szFunc);
        // Load Cron (now that we have the server Nym.
        // (I WAS loading this erroneously in Server.Init(), before
        // the Nym had actually been loaded from disk. That didn't work.)
        //
        const Identifier NOTARY_ID(server_->m_strNotaryID);

        // Make sure the Cron object has a pointer to the server's Nym.
        // (For signing stuff...)
        //
        server_->m_Cron.SetNotaryID(NOTARY_ID);
        server_->m_Cron.SetServerNym(&server_->m_nymServer);

        if (!server_->m_Cron.LoadCron())
            Log::vError("%s: Failed loading Cron file. (Did you just create "
                        "this server?)\n",
                        szFunc);
        Log::vOutput(0, "%s: Loading the server contract...\n", szFunc);

        auto pContract = App::Me().Contract().Server(NOTARY_ID);

        if (pContract) {
            Log::Output(0, "\n** Main Server Contract Verified **\n");
            bSuccess = true;
        }
        else {
            Log::vOutput(0, "\n%s: Failed reading Main Server Contract:\n\n",
                         szFunc);
        }
    }

    return bSuccess;
}

} // namespace opentxs
