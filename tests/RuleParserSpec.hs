module RuleParserSpec where

import qualified Data.Either as Either

import Test.Hspec

import qualified Firerule.Format.RuleParser as RP
import qualified Firerule.CondTree as CT

spec =
    describe "rule parser" $ do
        it "parses default rules" $
            RP.parseFirewall
                "first: jmp1; second: jmp2; third: jmp1;" `shouldBe`
                (Right $ RP.Firewall [
                    RP.Rule "first" [RP.DefaultJump "jmp1"],
                    RP.Rule "second" [RP.DefaultJump "jmp2"],
                    RP.Rule "third" [RP.DefaultJump "jmp1"]
                                    ])
        it "parses single node rule" $
            RP.parseFirewall
                "first: jmp1 % cond1;" `shouldBe`
                (Right $ RP.Firewall [
                    RP.Rule "first"
                        [RP.Jump "jmp1"
                            (CT.Leaf (RP.Condition [(True, "cond1")]))]
                                     ])
        it "parses single node rule with args" $
            RP.parseFirewall
                "first: jmp1 % cond1 arg1 arg2;" `shouldBe`
                (Right $ RP.Firewall [
                    RP.Rule "first"
                        [RP.Jump "jmp1"
                            (CT.Leaf (RP.Condition [(True, "cond1"),
                                (True, "arg1"), (True, "arg2")]))]
                                     ])
        it "parses with substitutions" $
            RP.parseFirewall
                "first: jmp1 % jmp2, jmp2 % cond1;" `shouldBe`
                (Right $ RP.Firewall [
                    RP.Rule "first"
                        [RP.Jump "jmp1"
                            (CT.Leaf (RP.Condition [(True, "cond1")])),
                         RP.Jump "jmp2"
                            (CT.Leaf (RP.Condition [(True, "cond1")]))]
                                     ])
        it "parses with deep substitutions" $
            RP.parseFirewall
                "first: jmp1 % jmp2, jmp2 % cond1 arg1, jmp3 % jmp1;" `shouldBe`
                (Right $ RP.Firewall [
                    RP.Rule "first"
                        [RP.Jump "jmp1"
                            (CT.Leaf (RP.Condition [(True, "cond1"), (True, "arg1")])),
                         RP.Jump "jmp2"
                            (CT.Leaf (RP.Condition [(True, "cond1"), (True, "arg1")])),
                         RP.Jump "jmp3"
                            (CT.Leaf (RP.Condition [(True, "cond1"), (True, "arg1")]))]
                                     ])
        it "fails on simple recursion" $
            RP.parseFirewall "first: jmp1 % jmp2, jmp2 % jmp1;" `shouldSatisfy`
                Either.isLeft
        it "fails on deep recursion" $
            RP.parseFirewall "first: jmp1 % jmp3, jmp2 % cond1 & jmp1, jmp3 % cond2 | jmp2;" `shouldSatisfy`
                Either.isLeft
