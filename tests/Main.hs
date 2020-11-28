module Main where

import Test.Hspec

import qualified TestIPv4
import qualified TestIPv6
import qualified NetRuleSpec
import qualified RuleParserSpec
import qualified MatchExprSpec

main = hspec $ do
    describe "NetRuleSpec" NetRuleSpec.spec
    describe "RuleParserSpec" RuleParserSpec.spec
    describe "IPv4" TestIPv4.spec
    describe "IPv6" TestIPv6.spec
    describe "MatchExpr" MatchExprSpec.spec
