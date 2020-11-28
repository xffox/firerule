{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
module Firerule.IPv6(IPv6, ipv6net, ipv6bits, ipv6prefixLen, parseIPv6) where

import qualified Data.List as List
import qualified Data.Bits as Bits
import qualified Text.Parsec as Parsec
import Data.Word(Word8, Word16)
import Data.DoubleWord(Word128)
import Text.Printf(printf)
import Data.Bits((.&.), (.|.))

import qualified Firerule.ValueSet as VS
import qualified Firerule.IP as IP
import qualified Firerule.IPParser as IPParser

newtype IPv6 = IPv6 (IP.IPRaw IPv6Host)
    deriving (Eq, Ord, VS.Mergeable)
type IPv6Host = Word128
type IPv6Bytes = (Word16, Word16, Word16, Word16,
                 Word16, Word16, Word16, Word16)

ipv6net :: IPv6Bytes -> Word8 -> IPv6
ipv6net (b1, b2, b3, b4, b5, b6, b7, b8) prefixLen =
    let prefixLen' = min ipv6bits prefixLen
        dt = IP.packBlocks [b1, b2, b3, b4, b5, b6, b7, b8]
     in IPv6 $ IP.IPRaw (dt .&. IP.subnetMask ipv6bits prefixLen') prefixLen'

ipv6host :: IPv6Bytes -> IPv6
ipv6host bytes = ipv6net bytes ipv6bits

ipv6bits :: Word8
ipv6bits =
    let z = 0 :: IPv6Host
     in fromIntegral $ Bits.finiteBitSize z

ipv6prefixLen :: IPv6 -> Word8
ipv6prefixLen (IPv6 raw) = IP.rawPrefixLen raw

instance IP.IP IPv6 IPv6Host where
    toRaw (IPv6 raw) = raw
    fromRaw = IPv6

instance Show IPv6 where
    show (IPv6 (IP.IPRaw dt prefixLen)) =
        let bs = IP.unpackBlocks dt :: [Word16]
            gbs = List.groupBy (\left right -> (left == 0) == (right == 0)) bs
            ml = maximum $ map (\g -> if head g == 0 then length g else 0) gbs
            h = case List.span
                    (\g -> (head g /= 0) || (length g < ml)) gbs of
                (b, (c:e)) | ml > 1 ->
                    (hexify $ concat b) ++ [""] ++ (hexify $ concat e)
                _ -> hexify bs
         in printf "%s/%d" (List.intercalate ":" h) prefixLen
         where hexify [] = [""]
               hexify bs = map (printf "%x") bs

parseIPv6 :: String -> Either String IPv6
parseIPv6 inp =
    case Parsec.parse ipv6 "inp" inp of
      Right addr -> Right addr
      Left v -> Left $ "ipv6 parse failed: " ++ (show v)

ipv6 = do
    let blocks = 8
    [b1, b2, b3, b4, b5, b6, b7, b8] <-
        ((Parsec.sepBy1 IPParser.optionalHexInteger (Parsec.char ':')) >>=
            (parseStartBlocks blocks))
    m <- Parsec.option ipv6bits $ do
        Parsec.char '/'
        IPParser.boundedInteger 0 ipv6bits
    return $ ipv6net (b1, b2, b3, b4, b5, b6, b7, b8) m
    where
        parseStartBlocks sz (Nothing:bs@(Nothing:_)) =
            fmap (0:) $ parseBlocks (sz-1) bs
        parseStartBlocks sz ((Just b):bs) =
            fmap (b:) $ parseBlocks (sz-1) bs
        parseBlocks sz (Nothing:[Nothing]) = return $ replicate sz 0
        parseBlocks sz (Nothing:bs)
          | sz > length bs = do
              rs <- parseEndBlocks bs
              return $ (replicate (sz-length bs) 0) ++ rs
          | otherwise = fail "invalid number of blocks"
        parseBlocks sz ((Just b):bs) = fmap (b:) $ parseBlocks (sz-1) bs
        parseBlocks sz []
          | sz == 0 = return []
          | otherwise = fail "invalid number of blocks"
        parseEndBlocks ((Just b):bs) = fmap (b:) $ parseEndBlocks bs
        parseEndBlocks [] = return []
        parseEndBlocks _ = fail "invalid block"
