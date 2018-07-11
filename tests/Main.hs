module Main where

import Test.Framework (defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import qualified TestIPv4
import qualified TestIPv6

tests = [
        testGroup "ipv4" [
            testProperty "subnets" TestIPv4.prop_subnetsAlwaysLess,
            testProperty "subnets show-parse" TestIPv4.prop_showParseEquals
        ],
        testGroup "ipv6" [
            testProperty "subnets" TestIPv6.prop_subnetsAlwaysLess,
            testProperty "subnets show-parse" TestIPv6.prop_showParseEquals
        ]
    ]

main = defaultMain tests
