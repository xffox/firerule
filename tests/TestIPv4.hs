module TestIPv4 where

import Test.QuickCheck

import qualified Firerule.IPv4 as IPv4
import qualified Data.Word as W
import qualified Firerule.IP as IP
import qualified Firerule.ValueSet as VS

instance Arbitrary IPv4.IPv4 where
    arbitrary = do
        b1 <- arbitrary
        b2 <- arbitrary
        b3 <- arbitrary
        b4 <- arbitrary
        prefixLen <- choose (0, IPv4.ipv4bits)
        return $ IPv4.ipv4net (b1, b2, b3, b4) prefixLen

newtype LimitedPrefixLen = LimitedPrefixLen W.Word8
    deriving Show
instance Arbitrary LimitedPrefixLen where
    arbitrary = LimitedPrefixLen <$> choose (0, 12)

prop_subnetsAlwaysLess :: IPv4.IPv4 -> LimitedPrefixLen -> Bool
prop_subnetsAlwaysLess v (LimitedPrefixLen prefixLen) =
    let subnets = IP.subnets v prefixLen
     in all (\sn -> (VS.mergeJoin sn v == Just v) &&
         (VS.mergeIntersect sn v == [sn])) subnets

prop_showParseEquals :: IPv4.IPv4 -> Bool
prop_showParseEquals v = (IPv4.parseIPv4 $ show v) == (Right v)
