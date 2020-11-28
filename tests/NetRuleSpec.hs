module NetRuleSpec where

import Test.Hspec

import qualified Firerule.CondTree as CondTree
import qualified FireruleMonitor.NetRule as NetRule
import qualified FireruleMonitor.NetInfo as NetInfo

spec =
    describe "selector" $ do
        it "matches nothing for empty" $
            matchNetworks
                ([] :: [(String, CondTree.CondTree NetRule.Condition)])
                ["abc", "def"] `shouldBe` Nothing
        it "matches true subtree" $
            matchNetworks [
                ("first",
                    CondTree.Leaf (NetRule.ConnectionNameInclude ["ghi"])),
                ("second",
                    CondTree.NodeTrue)
                          ]
                ["abc", "def"] `shouldBe` Just "second"
        it "matches single network name" $
            matchNetworks [
                ("first",
                    CondTree.Leaf (NetRule.ConnectionNameInclude ["tst"])),
                ("second",
                    CondTree.Leaf (NetRule.ConnectionNameInclude ["abc"])),
                ("third",
                    CondTree.Leaf (NetRule.ConnectionNameInclude ["rst"]))
                          ]
                ["abc"] `shouldBe` Just "second"
        it "matches multiple network names" $
            matchNetworks [
                ("first",
                    CondTree.Leaf (NetRule.ConnectionNameInclude
                        ["tst1", "tst2"])),
                ("second",
                    CondTree.Leaf (NetRule.ConnectionNameInclude
                        ["abc1", "abc2"])),
                ("third",
                    CondTree.Leaf (NetRule.ConnectionNameInclude
                        ["rst1", "rst2"]))
                          ]
                ["abc2", "abc1"] `shouldBe` Just "second"
        it "not matches on extra network names" $
            matchNetworks [
                ("first",
                    CondTree.Leaf (NetRule.ConnectionNameInclude
                        ["abc"])),
                ("second",
                    CondTree.Leaf (NetRule.ConnectionNameInclude
                        ["def"]))
                          ]
                ["abc", "def"] `shouldBe` Nothing
        it "not matches on missing network names" $
            matchNetworks [
                ("first",
                    CondTree.Leaf (NetRule.ConnectionNameInclude
                        ["abc", "def"])),
                ("second",
                    CondTree.Leaf (NetRule.ConnectionNameInclude
                        ["def", "ghi"]))
                          ]
                ["abc", "ghi"] `shouldBe` Nothing
        it "matches multiple network names joined with and" $
            matchNetworks [
                ("first",
                    CondTree.NodeAnd
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["abc"]))
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["ghi"]))),
                ("second",
                    CondTree.NodeAnd
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["abc"]))
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["def"])))
                          ]
                ["abc", "def"] `shouldBe` Just "second"
        it "matches on excluded network names" $
            matchNetworks [
                ("first",
                    CondTree.NodeAnd
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["abc"]))
                        (CondTree.Leaf (NetRule.ConnectionNameExclude
                            ["ghi", "rst"]))),
                ("second",
                    CondTree.NodeAnd
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["def"]))
                        (CondTree.Leaf (NetRule.ConnectionNameExclude
                            ["abc", "rst"])))
                          ]
                ["abc", "def"] `shouldBe` Just "second"
        it "matches on excluded network names with reordered rules" $
            matchNetworks [
                ("first",
                    CondTree.NodeAnd
                        (CondTree.Leaf (NetRule.ConnectionNameExclude
                            ["ghi", "rst"]))
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["abc"]))),
                ("second",
                    CondTree.NodeAnd
                        (CondTree.Leaf (NetRule.ConnectionNameExclude
                            ["abc", "rst"]))
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["def"])))
                          ]
                ["abc", "def"] `shouldBe` Just "second"
        it "matches alternate network names" $
            matchNetworks [
                ("first",
                    CondTree.NodeOr
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["abc"]))
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["ghi", "rst"]))),
                ("second",
                    CondTree.NodeOr
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["def"]))
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["abc", "rst"]))),
                ("third",
                    CondTree.NodeOr
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["rst"]))
                        (CondTree.Leaf (NetRule.ConnectionNameInclude
                            ["def", "rst"])))
                          ]
                ["rst", "def"] `shouldBe` Just "third"
        it "not matches partially" $
            matchNetworks [
                ("first",
                    CondTree.Leaf (NetRule.ConnectionNameInclude
                        ["abc", "def"]))
                          ]
                ["abcd", "cdef"] `shouldBe` Nothing
        it "matches regexes" $
            matchNetworks [
                ("first",
                    CondTree.Leaf (NetRule.ConnectionNameInclude
                        ["abc.*", ".*def"]))
                          ]
                ["abcd", "cdef"] `shouldBe` Just "first"

matchNetworks rules networks =
    let selector =
            NetRule.makeSelector (NetRule.NetRule rules)
     in NetRule.selectNetRule selector $ NetInfo.NetInfo networks
