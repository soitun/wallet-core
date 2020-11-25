// Copyright © 2017-2020 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "HexCoding.h"
#include "PublicKey.h"
#include "Solana/Address.h"
#include "Solana/Transaction.h"

#include "BinaryCoding.h"

#include <gtest/gtest.h>

using namespace TW;
using namespace TW::Solana;

TEST(SolanaTransaction, TransferMessageData) {
    auto from = Address("6eoo7i1khGhVm8tLBMAdq4ax2FxkKP4G7mCcfHyr3STN");
    auto to = Address("56B334QvCDMSirsmtEJGfanZm8GqeQarrSjdAb2MbeNM");
    Solana::Hash recentBlockhash("11111111111111111111111111111111");
    auto transaction = Transaction(from, to, 42, recentBlockhash);

    auto expectedHex =
        "0100010353f9d600fe925083bb399907ea648d23a6a081fc7e9059202fd725f7edd281dd3cc1ff9ba3c7a876c8"
        "082df2f8a36ea9342ce3819dd4b6fa72d4a18e04a5363a00000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000010202"
        "00010c020000002a00000000000000";
    ASSERT_EQ(hex(transaction.messageData()), expectedHex);
}

TEST(SolanaTransaction, TransferSerializeTransaction) {
    auto from = Address("41a5jYky56M6EWDsFfLaZRxoRtgAJSRWxJnxaJNJELn5");
    auto to = Address("4iSnyfDKaejniaPc2pBBckwQqV3mDS93go15NdxWJq2y");
    Solana::Hash recentBlockhash("11111111111111111111111111111111");
    auto transaction = Transaction(from, to, 42, recentBlockhash);
    Signature signature(
        "46SRiQGvtPb1iivDfnuC3dW1GzXkfQPTjdUyvFqF2sdPvFrsfx94fys2xpNKR6UiAj7RgKWdJG6mEfe85up6i1JT");
    transaction.signatures.clear();
    transaction.signatures.push_back(signature);

    auto expectedString =
        "5SiHeYyuDgjHxWHbYXSSPfmYc8s7EYZ8bdZ7j15z9Bj1yyZA3Bia9uWkRdXVkuqifXiiQj6fVKy"
        "7UkCL5kvv6iKrfjWTZ3szMVssTFxgJ7p8UJ7Mgg2uhHejVJvbzbiHHLbNVuJFs6kBxddnJ2yjWU"
        "Cp2dYJgjmphfA8hRHHdPH4Rv6znxEhD8q9XY4nByRPL7oMCo32oxeJn5rGbUZdCkapRUXG7zU9w"
        "hv6KjBktcUQZRCahhowGJT4UM5yCNCsUcqY9yan7UxqPyJgaFPuq4duqWJtQ39bTQ36X";
    ASSERT_EQ(transaction.serialize(), expectedString);
}

TEST(SolanaTransaction, TransferTransactionPayToSelf) {
    auto from = Address("zVSpQnbBZ7dyUWzXhrUQRsTYYNzoAdJWHsHSqhPj3Xu");
    auto to = Address("zVSpQnbBZ7dyUWzXhrUQRsTYYNzoAdJWHsHSqhPj3Xu");
    Solana::Hash recentBlockhash("11111111111111111111111111111111");
    auto transaction = Transaction(from, to, 42, recentBlockhash);
    Signature signature(
        "3CFWDEK51noPJP4v2t8JZ3qj7kC7kLKyws9akfHMyuJnQ35EtzBptHqvaHfeswiLsvUSxzMVNoj4CuRxWtDD9zB1");
    transaction.signatures.clear();
    transaction.signatures.push_back(signature);

    auto expectedString =
        "EKUmihvvUPKVN4GSCFwZRtz8WiyAuPvthW69Smo19SCjcPLQ6T7EVZd1HU71WAoe1bfgmPNS5JhU7ZLA9XKG3qbZqe"
        "EFJ1xmRwW9ZKw8SKMAL6VRWxp87oLu7PSmf5b8R34vCaww3XLKtZkoP49a7TUK31DqPN5xJCceMB3BZJyaojQaKU8n"
        "UkzSGf89LY6abZXp9krKAebvc6bSMzTP8SHSvbmZbf3VtejmpQeN9X6e7WVDn6oDa2bGT";
    ASSERT_EQ(transaction.serialize(), expectedString);
}

TEST(SolanaTransaction, StakeSerializeTransaction) {
    auto signer = Address("zVSpQnbBZ7dyUWzXhrUQRsTYYNzoAdJWHsHSqhPj3Xu");
    auto voteAddress = Address("4jpwTqt1qZoR7u6u639z2AngYFGN3nakvKhowcnRZDEC");
    auto programId = Address("Stake11111111111111111111111111111111111111");
    Solana::Hash recentBlockhash("11111111111111111111111111111111");
    auto stakeAddress = addressFromValidatorSeed(signer, voteAddress, programId);
    auto message = Message(signer, stakeAddress, voteAddress, 42, recentBlockhash);
    auto transaction = Transaction(message);
    Signature signature(
        "4Q3ctvLybffZJBGdvrnEg171AjZeiMPGf3rVfGCpDVZRq9QaKVw8jWTMqHzZckGi2yXbGoQdBgeua24iMfPGHTtV");
    transaction.signatures.clear();
    transaction.signatures.push_back(signature);

    auto expectedString =
        "7gcsGMV8fPkuSDegrBk5KF4eZtmGqdixEr5Kxx7m74nErH5EWxkKcvy5LKg3kqKHLMtzqGXrM8EdVskLu5k6cQUVmz"
        "nfd6iGpuDkn4BWi8HaqSoaeL7DCx6QHLUwcyvorfqPkgSaYopY9MeB6MGKS4bKCQi1paP7eEKZj9JgAZTHnpzAuFzq"
        "E5dC98MrbThoBmHqfybw1jHssp4NZjrxsuMz4oYcHe837WmnpinE68QEVf9FzuoXKrMDwYZQYogJHUZgxghvMmJu3X"
        "VZk7hL1h7SgE9ow2SvvNfAUYfUTuz8N9m6JcXgwmNL51ZweW9F1fekmSKE3vLEAaVvvYFsDxn1gt4bXuTdAMuUDKdH"
        "33YMLQr8eEsdUDZUm33KtuE7Ddy84NEg3KbpWAy8T4vkwiLyvoyjmMdzCkMuobyXWQV1rfRk5vTJ4x6dMgznfAeKEq"
        "md6xZ2hN8JBmTenP5dsvZCCSCf4G7cUkdndKu552KALqiNHd5msgLJvJKSHmZjFhS43fDCvkG7njF8yaZzWjmAknWU"
        "BbV6YaGmD3XmcWfJgvB1zivZJhiMbzopP8Nm5wL5iDbCrSZTGq2tzEsTvje75wv2RtuAcgiicEPTuPAin9fKyMbCpf"
        "67pGgWPwH5DwYumMwd8zwoJyuakyqFsFLnBKTvp8pFCijdj7fEhyC31xuMV7crwyrN5X3y7QKCE7PZcBP637YHEPtT"
        "vt1ECp4CqBSnvPc8vRD8EMhHe5jRFSDkQriUenEPFc51dTDTJWL26xuiTivktEm6ahHq5d6MPr4NRDvcRG2cZvEgxH"
        "BLpKfuB5XL3JfQZ3Nn3B916gaK8owz9Rk2e3";
    ASSERT_EQ(transaction.serialize(), expectedString);
}

TEST(SolanaTransaction, CreateTokenAccountTransaction) {
    auto signer = Address("B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V");
    auto token = Address("SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt");
    auto tokenAddress = Address("EDNd1ycsydWYwVmrYZvqYazFqwk1QjBgAUKFjBoz1jKP");
    Solana::Hash recentBlockhash("9ipJh5xfyoyDaiq8trtrdqQeAhQbQkWy2eANizKvx75K");
    auto message = Message(signer, TokenInstruction::Token_CreateAccount, token, tokenAddress, recentBlockhash);
    EXPECT_EQ(message.header.numRequiredSignatures, 1);
    EXPECT_EQ(message.header.numCreditOnlySignedAccounts, 0);
    EXPECT_EQ(message.header.numCreditOnlyUnsignedAccounts, 5);
    ASSERT_EQ(message.accountKeys.size(), 7);
    EXPECT_EQ(message.accountKeys[0].string(), "B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V");
    EXPECT_EQ(message.accountKeys[1].string(), "EDNd1ycsydWYwVmrYZvqYazFqwk1QjBgAUKFjBoz1jKP");
    EXPECT_EQ(message.accountKeys[2].string(), "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt");
    EXPECT_EQ(message.accountKeys[3].string(), "11111111111111111111111111111111");
    EXPECT_EQ(message.accountKeys[4].string(), "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    EXPECT_EQ(message.accountKeys[5].string(), "SysvarRent111111111111111111111111111111111");
    EXPECT_EQ(message.accountKeys[6].string(), "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
    EXPECT_EQ(Base58::bitcoin.encode(message.recentBlockhash.bytes), "9ipJh5xfyoyDaiq8trtrdqQeAhQbQkWy2eANizKvx75K");
    ASSERT_EQ(message.instructions.size(), 1);
    EXPECT_EQ(message.instructions[0].programId.string(), "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
    ASSERT_EQ(message.instructions[0].accounts.size(), 7);
    EXPECT_EQ(message.instructions[0].accounts[0].string(), "B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V");
    EXPECT_EQ(message.instructions[0].accounts[1].string(), "EDNd1ycsydWYwVmrYZvqYazFqwk1QjBgAUKFjBoz1jKP");
    EXPECT_EQ(message.instructions[0].accounts[2].string(), "B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V");
    EXPECT_EQ(message.instructions[0].accounts[3].string(), "SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt");
    EXPECT_EQ(message.instructions[0].accounts[4].string(), "11111111111111111111111111111111");
    EXPECT_EQ(message.instructions[0].accounts[5].string(), "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    EXPECT_EQ(message.instructions[0].accounts[6].string(), "SysvarRent111111111111111111111111111111111");
    auto transaction = Transaction(message);
    transaction.signatures.clear();
    Signature signature("3doYbPs5rES3TeDSrntqUvMgXCDE2ViJX2SFhLtiptVNkqPuixXs1SwU5LUZ3KwHnCzDUth6BRr3vU3gqnuUgRvQ");
    transaction.signatures.push_back(signature);

    auto expectedString =
        // test data obtained from spl-token create-account
        "CKzRLx3AQeVeLQ7T4hss2rdbUpuAHdbwXDazxtRnSKBuncCk3WnYgy7XTrEiya19MJviYHYdTxi9gmWJY8qnR2vHVnH2DbPiKA8g72rD3VvMnjosGUBBvCwbBLge6FeQdgczMyRo9n5PcHvg9yJBTJaEEvuewyBVHwCGyGQci7eYd26xtZtCjAjwcTq4gGr3NZbeRW6jZp6j6APuew7jys4MKYRV4xPodua1TZFCkyWZr1XKzmPh7KTavtN5VzPDA8rbsvoEjHnKzjB2Bszs6pDjcBFSHyQqGsHoF8XPD35BLfjDghNtBmf9cFqo5axa6oSjANAuYg6cMSP4Hy28waSj8isr6gQjE315hWi3W1swwwPcn322gYZx6aMAcmjczaxX9aktpHYgZxixF7cYWEHxJs5QUK9mJePu9Xc6yW75UB4Ynx6dUgaSTEUzoQthF2TN3xXwu1";
    EXPECT_EQ(transaction.serialize(), expectedString);
}

TEST(SolanaTransaction, TransferTokenTransaction) {
    auto signer = Address("B1iGmDJdvmxyUiYM8UEo2Uw2D58EmUrw4KyLYMmrhf8V");
    auto token = Address("SRMuApVNdxXokk5GT7XD5cUUgXMBCoAz2LHeuAoKWRt");
    auto senderTokenAddress = Address("EDNd1ycsydWYwVmrYZvqYazFqwk1QjBgAUKFjBoz1jKP");
    auto recipientTokenAddress = Address("3WUX9wASxyScbA7brDipioKfXS1XEYkQ4vo3Kej9bKei");
    uint64_t amount = 10000;
    uint8_t decimals = 6;
    Solana::Hash recentBlockhash("9ipJh5xfyoyDaiq8trtrdqQeAhQbQkWy2eANizKvx75K");
    auto message = Message(signer, TokenInstruction::Token_Transfer, token, senderTokenAddress, recipientTokenAddress, amount, decimals, recentBlockhash);
    EXPECT_EQ(message.header.numRequiredSignatures, 1);
    EXPECT_EQ(message.header.numCreditOnlySignedAccounts, 0);
    EXPECT_EQ(message.header.numCreditOnlyUnsignedAccounts, 2);
    ASSERT_EQ(message.accountKeys.size(), 5);
    ASSERT_EQ(message.instructions.size(), 1);
    EXPECT_EQ(message.instructions[0].programId.string(), "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    ASSERT_EQ(message.instructions[0].accounts.size(), 4);
    auto transaction = Transaction(message);
    transaction.signatures.clear();
    Signature signature("4zsTa4Y6fG7qWRw8zyZW6qQyAE2t4eBR8LyWUpxYfouTTMNughmvYsfoNsihQLURhkcxYByFZNne25SeLuxgJ5Zz");
    transaction.signatures.push_back(signature);

    auto expectedString =
        // test data obtained from spl-token create-account
        "SFEo5WZa5b84MmhmyTXuKEoVr9MkiqKKjQXcrVjv8irfs8UppgbmkeJNnPSbRSrVAXUVJ5xox3xxXWhtdqob62sHMQYe3BkodWYhzinUmqf7PUaDow88kaH1NKVcw9jxa7Z3MToYPcvvRJ58ewE4ax7h8pQnoj4nnWeJW4fEaiiAQBNQxQwuQvv4Yd4J7txTUUfniuhQSdPg3NhjTEvrELcSedNjSLrQtMY3obvVqtG9wZmXJLd8T46Ar1LqzbNWZ9ELsyP9E2zSePr8jtXCKy3cMAvfcfjf7Dr575PLG1uwYEYUfPtXwRGvkjpTageTz76em2PPEANtvqKDxHbEcLeoPqha7PuTwtxrPGEbcXUAgqVfnKodfVs2rL2h";
    EXPECT_EQ(transaction.serialize(), expectedString);
}
