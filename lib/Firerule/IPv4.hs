{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeSynonymInstances #-}
module Firerule.IPv4(IPv4, ipv4net, ipv4bits, parseIPv4) where

import Data.Word(Word8, Word32)
import qualified Data.Bits as Bits
import qualified Text.Parsec as Parsec
import Text.Printf(printf)
import Data.Bits((.&.), (.|.))

import qualified Firerule.ValueSet as VS
import qualified Firerule.IP as IP
import qualified Firerule.IPParser as IPParser

newtype IPv4 = IPv4 (IP.IPRaw IPv4Host)
    deriving Eq
type IPv4Host = Word32
type IPv4Bytes = (Word8, Word8, Word8, Word8)

ipv4host :: IPv4Bytes -> IPv4
ipv4host bytes = ipv4net bytes ipv4bits
ipv4net :: IPv4Bytes -> Word8 -> IPv4
ipv4net (b1, b2, b3, b4) prefixLen =
    let dt = IP.packBlocks [b1, b2, b3, b4]
     in IPv4 $ IP.IPRaw (dt .&. IP.subnetMask ipv4bits prefixLen) prefixLen

ipv4bits :: Word8
ipv4bits =
    let z = 0 :: IPv4Host
     in fromIntegral $ Bits.finiteBitSize z

instance IP.IP IPv4 IPv4Host where
    toRaw (IPv4 raw) = raw
    fromRaw raw = (IPv4 raw)

instance VS.Mergeable IPv4 where
    mergeJoin v1@(IPv4 raw1) v2@(IPv4 raw2) =
        fmap IPv4 $ VS.mergeJoin raw1 raw2
    mergeIntersect v1@(IPv4 raw1) v2@(IPv4 raw2) =
        fmap IPv4 $ VS.mergeIntersect raw1 raw2

instance Show IPv4 where
    show (IPv4 (IP.IPRaw dt prefixLen)) =
        let [b1, b2, b3, b4] = IP.unpackBlocks dt :: [Word8]
        in printf "%hhu.%hhu.%hhu.%hhu/%d" b1 b2 b3 b4 prefixLen

parseIPv4 :: String -> Either String IPv4
parseIPv4 inp =
    case Parsec.parse ipv4 "inp" inp of
      Right addr -> Right addr
      Left v -> Left $ "ipv4 parse failed: " ++ (show v)

ipv4 = do
    bs <- Parsec.sepBy1 IPParser.integer (Parsec.char '.')
    m <- Parsec.option ipv4bits $ do
            Parsec.char '/'
            IPParser.boundedInteger 0 ipv4bits
    if length bs == 4
       then do
           let [b1, b2, b3, b4] = bs
           return $ ipv4net (b1, b2, b3, b4) m
       else fail "ipv4 invalid number of blocks"
