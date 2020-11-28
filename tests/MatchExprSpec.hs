module MatchExprSpec where

import qualified Data.Map as Map

import Test.Hspec

import qualified Firerule.Iptables.MatchExpr as MatchExpr
import qualified Firerule.ValueSet as VS
import qualified Firerule.Iptables.IptablesData as Data
import qualified Firerule.IPv4 as IPv4

spec =
    describe "match expr" $ do
        it "intersects same values" $ do
            let val = Map.fromList [
                 (MatchExpr.MatchProtocol, (True, Data.SrcPort 22)),
                 (MatchExpr.MatchDestination, (True, Data.Destination
                    (Data.IPv4 (IPv4.ipv4host (192, 168, 1, 1)))))
                                   ]
            VS.simpleValue (VS.intersection val val) `shouldBe` Just val
        it "joins same values" $ do
            let val = Map.fromList [
                 (MatchExpr.MatchProtocol, (True, Data.SrcPort 22)),
                 (MatchExpr.MatchDestination, (True, Data.Destination
                    (Data.IPv4 (IPv4.ipv4host (192, 168, 1, 1)))))
                                   ]
            VS.simpleValue (VS.union val val) `shouldBe` Just val
        it "eliminates opposites" $ do
            let val1 = Map.fromList [
                 (MatchExpr.MatchSrcPort, (True, Data.SrcPort 22))
                                    ]
                val2 = Map.fromList [
                 (MatchExpr.MatchSrcPort, (False, Data.SrcPort 22))
                                    ]
            VS.simpleValue (VS.union val1 val2) `shouldBe` Just Map.empty
        it "joins subnets" $ do
            let val1 = Map.fromList [
                 (MatchExpr.MatchSource,
                     (True, Data.Source (Data.IPv4
                        (IPv4.ipv4net (192,168,1,0) 32))))
                                    ]
                val2 = Map.fromList [
                    (MatchExpr.MatchSource,
                     (True, Data.Source (Data.IPv4
                        (IPv4.ipv4net (192,168,1,1) 32))))
                                   ]
            VS.simpleValue (VS.union val1 val2) `shouldBe` (Just $ Map.fromList [
                 (MatchExpr.MatchSource,
                     (True, Data.Source (Data.IPv4
                        (IPv4.ipv4net (192,168,1,0) 31))))
                                   ])
        it "eliminates extra values" $ do
            let val1 = Map.fromList [
                 (MatchExpr.MatchProtocol, (True, Data.Protocol Data.TCP)),
                 (MatchExpr.MatchSrcPort, (True, Data.SrcPort 22))
                                    ]
                val2 = Map.fromList [
                 (MatchExpr.MatchSrcPort, (True, Data.SrcPort 22))
                                    ]
            VS.simpleValue (VS.union val1 val2) `shouldBe` Just val2
        it "joins when some parts are equal" $ do
            let val1 = Map.fromList [
                 (MatchExpr.MatchProtocol, (True, Data.Protocol Data.TCP)),
                 (MatchExpr.MatchSource,
                     (True, Data.Source (Data.IPv4
                        (IPv4.ipv4net (192,168,1,0) 32))))
                                    ]
                val2 = Map.fromList [
                 (MatchExpr.MatchProtocol, (True, Data.Protocol Data.TCP)),
                 (MatchExpr.MatchSource,
                     (True, Data.Source (Data.IPv4
                        (IPv4.ipv4net (192,168,1,1) 32))))
                                    ]
            VS.simpleValue (VS.union val1 val2) `shouldBe` (Just $
                Map.fromList [
                 (MatchExpr.MatchProtocol, (True, Data.Protocol Data.TCP)),
                 (MatchExpr.MatchSource,
                     (True, Data.Source (Data.IPv4
                        (IPv4.ipv4net (192,168,1,0) 31))))
                             ])
