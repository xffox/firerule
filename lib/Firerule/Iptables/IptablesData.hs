{-# LANGUAGE FlexibleInstances #-}
module Firerule.Iptables.IptablesData where

import Data.Word (Word16)
import qualified Data.Set as Set

import qualified Firerule.IPv4 as IPv4
import qualified Firerule.IPv6 as IPv6
import qualified Firerule.ValueSet as VS

data Target = UserTarget String | SysTarget BuiltinTarget

data BuiltinTarget =
    Accept |
    Drop |
    Reject |
    Log |
    Return
    deriving Show

data Table =
    Filter |
    Nat |
    Mangle |
    Raw
    deriving (Eq, Ord, Show)

data Action = Goto String | Jump Target

data Network = IPv4Network | IPv6Network
    deriving (Eq, Ord, Show)

data CtState = CtEstablished | CtRelated
    deriving (Eq, Ord, Show)

data NetworkAddress = IPv4 IPv4.IPv4 | IPv6 IPv6.IPv6
    deriving (Eq)

instance Show NetworkAddress where
    show (IPv4 addr) = show addr
    show (IPv6 addr) = show addr

instance VS.Mergeable NetworkAddress where
    mergeIntersect (IPv4 addr1) (IPv4 addr2) = fmap IPv4 $ VS.mergeIntersect addr1 addr2
    mergeIntersect (IPv6 addr1) (IPv6 addr2) = fmap IPv6 $ VS.mergeIntersect addr1 addr2
    mergeIntersect _ _ = []
    mergeJoin (IPv4 addr1) (IPv4 addr2) = fmap IPv4 $ VS.mergeJoin addr1 addr2
    mergeJoin (IPv6 addr1) (IPv6 addr2) = fmap IPv6 $ VS.mergeJoin addr1 addr2
    mergeJoin _ _ = Nothing

data Protocol = TCP | UDP | ICMP | ICMPv6
    deriving (Show, Eq)

instance VS.Mergeable Protocol where
    mergeIntersect TCP TCP = [TCP]
    mergeIntersect UDP UDP = [UDP]
    mergeIntersect ICMP ICMP = [ICMP]
    mergeIntersect ICMPv6 ICMPv6 = [ICMPv6]
    mergeIntersect _ _ = []
    mergeJoin TCP TCP = Just TCP
    mergeJoin UDP UDP = Just UDP
    mergeJoin ICMP ICMP = Just ICMP
    mergeJoin ICMPv6 ICMPv6 = Just ICMPv6
    mergeJoin t1 t2 = Nothing

data MatchValue =
    Source NetworkAddress |
    Destination NetworkAddress |
    Protocol Protocol |
    InInterface String |
    OutInterface String |
    SrcPort Word16 |
    DstPort Word16 |
    State (Set.Set CtState)
    deriving (Show, Eq)

instance VS.Mergeable MatchValue where
    mergeIntersect (Source n1) (Source n2) = fmap Source $ VS.mergeIntersect n1 n2
    mergeIntersect (Destination n1) (Destination n2) = fmap Destination $ VS.mergeIntersect n1 n2
    mergeIntersect (Protocol n1) (Protocol n2) = fmap Protocol $ VS.mergeIntersect n1 n2
    mergeIntersect (InInterface n1) (InInterface n2)
        | n1 == n2 = [InInterface n1]
        | otherwise = []
    mergeIntersect (OutInterface n1) (OutInterface n2)
        | n1 == n2 = [OutInterface n1]
        | otherwise = []
    mergeIntersect (SrcPort p1) (SrcPort p2)
        | p1 == p2 = [SrcPort p1]
        | otherwise = []
    mergeIntersect (DstPort p1) (DstPort p2)
        | p1 == p2 = [DstPort p1]
        | otherwise = []
    mergeIntersect (State left) (State right) =
        let sts = Set.intersection left right
         in if Set.null sts then [] else [State sts]
    mergeIntersect left right = [left, right]
    mergeJoin (Source n1) (Source n2) = fmap Source $ VS.mergeJoin n1 n2
    mergeJoin (Destination n1) (Destination n2) = fmap Destination $ VS.mergeJoin n1 n2
    mergeJoin (Protocol n1) (Protocol n2) = fmap Protocol $ VS.mergeJoin n1 n2
    mergeJoin in1@(InInterface n1) in2@(InInterface n2)
        | n1 == n2 = Just (InInterface n1)
        | otherwise = Nothing
    mergeJoin in1@(OutInterface n1) in2@(OutInterface n2)
        | n1 == n2 = Just (OutInterface n1)
        | otherwise = Nothing
    mergeJoin t1@(SrcPort p1) t2@(SrcPort p2)
        | p1 == p2 = Just (SrcPort p1)
        | otherwise = Nothing
    mergeJoin t1@(DstPort p1) t2@(DstPort p2)
        | p1 == p2 = Just (DstPort p1)
        | otherwise = Nothing
    mergeJoin (State left) (State right) = Just $ State $ Set.union left right
    mergeJoin left right = Nothing

type BoolMatchValue = (MatchValue, Bool)

-- TODO: fix false cases
instance VS.Mergeable BoolMatchValue where
    mergeIntersect (left, True) (right, True) =
        fmap (\r -> (r, True)) $ VS.mergeIntersect left right
    mergeIntersect left right = [left, right]
    mergeJoin (left, True) (right, True) =
        fmap (\r -> (r, True)) $ VS.mergeJoin left right
    mergeJoin _ _ = Nothing
