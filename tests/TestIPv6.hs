module TestIPv6 where

import Test.QuickCheck
import Test.Hspec

import qualified Firerule.IPv6 as IPv6
import qualified Data.Word as W
import qualified Firerule.IP as IP
import qualified Firerule.ValueSet as VS

instance Arbitrary IPv6.IPv6 where
    arbitrary = do
        b1 <- arbitrary
        b2 <- arbitrary
        b3 <- arbitrary
        b4 <- arbitrary
        b5 <- arbitrary
        b6 <- arbitrary
        b7 <- arbitrary
        b8 <- arbitrary
        prefixLen <- choose (0, IPv6.ipv6bits)
        return $ IPv6.ipv6net (b1, b2, b3, b4, b5, b6, b7, b8) prefixLen

newtype LimitedPrefixLen = LimitedPrefixLen W.Word8
    deriving Show
instance Arbitrary LimitedPrefixLen where
    arbitrary = LimitedPrefixLen <$> choose (0, 12)

prop_subnetsAlwaysLess :: IPv6.IPv6 -> LimitedPrefixLen -> Bool
prop_subnetsAlwaysLess v (LimitedPrefixLen prefixLen) =
    let subnets = IP.subnets v
            (min IPv6.ipv6bits (IPv6.ipv6prefixLen v + prefixLen))
     in all (\sn -> (VS.simpleValue (VS.union sn v) == Just v) &&
         (VS.simpleValue (VS.intersection sn v) == Just sn)) subnets

prop_showParseEquals :: IPv6.IPv6 -> Bool
prop_showParseEquals v = (IPv6.parseIPv6 $ show v) == (Right v)

spec = describe "IPv6" $ do
    it "does subnets" $ property prop_subnetsAlwaysLess
    it "does show-parse" $ property prop_showParseEquals
