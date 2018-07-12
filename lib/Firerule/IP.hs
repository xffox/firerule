{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FunctionalDependencies #-}
module Firerule.IP where

import qualified Data.Word as W
import qualified Data.Bits as Bits
import qualified Data.List as List
import Data.Bits((.&.), (.|.))

import qualified Firerule.ValueSet as VS

data IPRaw w = IPRaw w W.Word8
    deriving Eq

rawPrefixLen (IPRaw _ prefixLen) = prefixLen

subnets :: (IP p w) => p -> W.Word8 -> [p]
subnets v len =
    let (IPRaw host prefixLen) = toRaw v
        bits = fromIntegral $ Bits.finiteBitSize host
     in if len <= prefixLen
           then []
           else let (b, e) = range host prefixLen bits
                    step = 2^(bits-len)
                 in map (\v -> fromRaw (IPRaw v len)) [b, b+step .. e]

class (Enum w, Num w, Bits.FiniteBits w) => IP p w | p -> w where
    toRaw :: p -> IPRaw w
    fromRaw :: IPRaw w -> p

packBlocks :: (Bits.FiniteBits a, Num b, Bits.Bits b, Integral a) => [a] -> b
packBlocks [] = 0
packBlocks bs =
    let bsz = Bits.finiteBitSize $ head bs
        blocks = length bs
     in List.foldl' (.|.) 0 $
             map (\(i, b) -> Bits.shift (fromIntegral b) (bsz*i)) $
                 zip [blocks-1, blocks-2..] bs

unpackBlocks :: (Num a, Bits.FiniteBits a, Bits.Bits a,
    Bits.FiniteBits b, Bits.Bits b, Integral b) => b -> [a]
unpackBlocks v =
    let bsz = Bits.finiteBitSize $ head res
        vsz = Bits.finiteBitSize v
        mask = (Bits.bit bsz) - 1
        blocks = (vsz-1) `div` bsz + 1
        res = map (\i -> fromIntegral $ Bits.shift v (-bsz*i) .&. mask)
            [(blocks-1), (blocks-2) .. 0]
     in res

subnetMask bits prefixLen = Bits.complement $ hostMask bits prefixLen
hostMask bits prefixLen = Bits.bit (fromIntegral (bits - prefixLen)) - 1

range dt prefixLen bits = (dt, dt + 2^(bits-prefixLen) - 1)

sizeBits w = fromIntegral $ Bits.finiteBitSize w

instance (Bits.FiniteBits w, Num w, Ord w) => VS.Mergeable (IPRaw w) where
    mergeJoin v1@(IPRaw dt1 prefixLen1)
        v2@(IPRaw dt2 prefixLen2)
        | v1 == v2 = Just v1
        | prefixLen1 > 0 && prefixLen1 == prefixLen2 =
            let m = subnetMask (sizeBits dt1) $ prefixLen1-1
             in if ((dt1 .&. m) == (dt2 .&. m)) &&
                 ((dt1 `Bits.xor` dt2) /= 0)
                then Just $ (IPRaw (dt1 .&. m) (prefixLen1-1))
                else Nothing
        | otherwise =
            let minPrefixLen = min prefixLen1 prefixLen2
             in let m = subnetMask (sizeBits dt1) minPrefixLen
                 in if dt1 .&. m == dt2 .&. m
                       then Just $ (IPRaw (dt1 .&. m) minPrefixLen)
                       else Nothing
    mergeIntersect v1@(IPRaw host1 prefixLen1)
        v2@(IPRaw host2 prefixLen2) =
        let (b1, e1) = range host1 prefixLen1 (sizeBits host1)
            (b2, e2) = range host2 prefixLen2 (sizeBits host1)
            sectBegin = max b1 b2
            sectEnd = min e1 e2
        in if sectBegin <= sectEnd
            then [IPRaw sectBegin (max prefixLen1 prefixLen2)]
            else []
