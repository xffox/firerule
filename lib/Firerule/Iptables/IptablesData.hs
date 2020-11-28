{-# LANGUAGE FlexibleInstances #-}
module Firerule.Iptables.IptablesData where

import Data.Word (Word16)
import qualified Data.Set as Set

import qualified Firerule.IPv4 as IPv4
import qualified Firerule.IPv6 as IPv6
import qualified Firerule.ValueSet as VS
import qualified Firerule.Wrapped as Wrapped

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
    deriving (Eq, Ord)

instance Show NetworkAddress where
    show (IPv4 addr) = show addr
    show (IPv6 addr) = show addr

instance Wrapped.WrappedMergeable NetworkAddress where
    unwrap f (IPv4 _) = f (extractIPv4, IPv4)
        where extractIPv4 (IPv4 v) = Just v
              extractIPv4 _ = Nothing
    unwrap f (IPv6 _) = f (extractIPv6, IPv6)
        where extractIPv6 (IPv6 v) = Just v
              extractIPv6 _ = Nothing

instance VS.Mergeable NetworkAddress where
    intersection = Wrapped.intersectionWrapped
    union = Wrapped.unionWrapped
    emptySet = Nothing
    universeSet = Nothing

data Protocol = TCP | UDP | ICMP | ICMPv6
    deriving (Show, Eq, Ord)

instance VS.Mergeable Protocol where
    intersection t1 t2
      | t1 == t2 = VS.fromValue t1
      | otherwise = VS.fromCategory VS.EmptySet
    union t1 t2
      | t1 == t2 = VS.fromValue t1
      | otherwise = VS.fromCategory VS.SomeSet
    emptySet = Nothing
    universeSet = Nothing

data MatchValue =
    AnyValue |
    Source NetworkAddress |
    Destination NetworkAddress |
    Protocol Protocol |
    InInterface String |
    OutInterface String |
    SrcPort Word16 |
    DstPort Word16 |
    State (Set.Set CtState)
    deriving (Show, Eq, Ord)

instance VS.Mergeable MatchValue where
    intersection (Source n1) (Source n2) =
        Wrapped.mapSimpleValue Source $ VS.intersection n1 n2
    intersection (Destination n1) (Destination n2) =
        Wrapped.mapSimpleValue Destination $ VS.intersection n1 n2
    intersection (Protocol n1) (Protocol n2) =
        Wrapped.mapSimpleValue Protocol $ VS.intersection n1 n2
    intersection (InInterface n1) (InInterface n2)
        | n1 == n2 = VS.fromValue $ InInterface n1
        | otherwise = VS.fromCategory VS.EmptySet
    intersection (OutInterface n1) (OutInterface n2)
        | n1 == n2 = VS.fromValue $ OutInterface n1
        | otherwise = VS.fromCategory VS.EmptySet
    intersection (SrcPort p1) (SrcPort p2)
        | p1 == p2 = VS.fromValue $ SrcPort p1
        | otherwise = VS.fromCategory VS.EmptySet
    intersection (DstPort p1) (DstPort p2)
        | p1 == p2 = VS.fromValue $ DstPort p1
        | otherwise = VS.fromCategory VS.EmptySet
    intersection (State left) (State right) =
        let sts = Set.intersection left right
         in if Set.null sts
               then VS.fromCategory VS.EmptySet
               else VS.fromValue $ State sts
    intersection AnyValue right = VS.fromValue right
    intersection left AnyValue = VS.fromValue left
    intersection left right = VS.fromCategory VS.SomeSet
    union (Source n1) (Source n2) =
        Wrapped.mapSimpleValue Source $ VS.union n1 n2
    union (Destination n1) (Destination n2) =
        Wrapped.mapSimpleValue Source $ VS.union n1 n2
    union (Protocol n1) (Protocol n2) =
        Wrapped.mapSimpleValue Protocol $ VS.union n1 n2
    union in1@(InInterface n1) in2@(InInterface n2)
        | n1 == n2 = VS.fromValue $ InInterface n1
        | otherwise = VS.fromCategory VS.SomeSet
    union in1@(OutInterface n1) in2@(OutInterface n2)
        | n1 == n2 = VS.fromValue $ OutInterface n1
        | otherwise = VS.fromCategory VS.SomeSet
    union t1@(SrcPort p1) t2@(SrcPort p2)
        | p1 == p2 = VS.fromValue $ SrcPort p1
        | otherwise = VS.fromCategory VS.SomeSet
    union t1@(DstPort p1) t2@(DstPort p2)
        | p1 == p2 = VS.fromValue $ DstPort p1
        | otherwise = VS.fromCategory VS.SomeSet
    union (State left) (State right) =
        VS.fromValue $ State $ Set.union left right
    union AnyValue _ = VS.fromValue AnyValue
    union _ AnyValue = VS.fromValue AnyValue
    union left right = VS.fromCategory VS.SomeSet
    emptySet = Nothing
    universeSet = Just AnyValue
